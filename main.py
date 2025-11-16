import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import Product, Order, AdminUser, OrderStatus

# Auth settings
SECRET_KEY = os.getenv("SECRET_KEY", "secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Mini Flipkart API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None


class LoginPayload(BaseModel):
    username: str
    password: str


# Helper functions for auth

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_admin(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    # Find in DB
    user = db["adminuser"].find_one({"username": token_data.username, "is_active": True})
    if not user:
        raise credentials_exception
    return user


@app.get("/")
def root():
    return {"message": "Mini Flipkart Backend Running"}


# Auth endpoints
@app.post("/auth/login", response_model=Token)
def login(payload: LoginPayload):
    user = db["adminuser"].find_one({"username": payload.username, "is_active": True})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": payload.username})
    return {"access_token": access_token, "token_type": "bearer"}


# Seed admin user if not exists
@app.post("/auth/seed-admin")
def seed_admin(username: str = Body(...), password: str = Body(...)):
    if db["adminuser"].find_one({"username": username}):
        return {"status": "exists"}
    hashed = get_password_hash(password)
    db["adminuser"].insert_one({"username": username, "password_hash": hashed, "role": "admin", "is_active": True})
    return {"status": "created"}


# Products public endpoints
@app.get("/products", response_model=List[Product])
def list_products(q: Optional[str] = None, category: Optional[str] = None):
    query = {"active": True}
    if q:
        query["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"categories": {"$elemMatch": {"$regex": q, "$options": "i"}}},
        ]
    if category:
        query["categories"] = {"$in": [category]}
    items = get_documents("product", query)
    # Convert _id to string for Pydantic
    for it in items:
        it.pop("_id", None)
    return items


@app.get("/products/{sku}", response_model=Product)
def get_product(sku: str):
    it = db["product"].find_one({"sku": sku, "active": True})
    if not it:
        raise HTTPException(404, "Product not found")
    it.pop("_id", None)
    return it


# Orders public endpoints
@app.post("/orders")
def create_order(order: Order):
    # Simple stock check (best-effort)
    for item in order.items:
        prod = db["product"].find_one({"sku": item.sku})
        if not prod:
            raise HTTPException(400, f"Product {item.sku} not found")
        # If stock matrix provided, ensure quantity available when size/color match
        if prod.get("stock"):
            match = next((s for s in prod["stock"] if s.get("size") == item.size and s.get("color") == item.color), None)
            if match and match.get("quantity", 0) < item.quantity:
                raise HTTPException(400, f"Insufficient stock for {item.sku}")
    oid = create_document("order", order)
    return {"order_id": oid}


@app.get("/orders/{order_id}")
def order_status(order_id: str):
    from bson import ObjectId
    try:
        doc = db["order"].find_one({"_id": ObjectId(order_id)})
    except Exception:
        raise HTTPException(404, "Order not found")
    if not doc:
        raise HTTPException(404, "Order not found")
    doc["id"] = str(doc.pop("_id"))
    return doc


# Admin product management
@app.post("/admin/products", response_model=dict)
def admin_create_product(product: Product, admin=Depends(get_current_admin)):
    # Ensure unique SKU
    if db["product"].find_one({"sku": product.sku}):
        raise HTTPException(400, "SKU already exists")
    pid = create_document("product", product)
    return {"id": pid}


@app.put("/admin/products/{sku}")
def admin_update_product(sku: str, product: Product, admin=Depends(get_current_admin)):
    existing = db["product"].find_one({"sku": sku})
    if not existing:
        raise HTTPException(404, "Product not found")
    data = product.model_dump()
    data["updated_at"] = datetime.now(timezone.utc)
    db["product"].update_one({"sku": sku}, {"$set": data})
    return {"status": "updated"}


@app.delete("/admin/products/{sku}")
def admin_delete_product(sku: str, admin=Depends(get_current_admin)):
    res = db["product"].delete_one({"sku": sku})
    if res.deleted_count == 0:
        raise HTTPException(404, "Product not found")
    return {"status": "deleted"}


@app.get("/admin/inventory")
def admin_inventory(admin=Depends(get_current_admin)):
    items = list(db["product"].find({}, {"name": 1, "sku": 1, "stock": 1, "active": 1}))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


class StockUpdate(BaseModel):
    stock: List[dict]


@app.put("/admin/inventory/{sku}")
def admin_update_stock(sku: str, payload: StockUpdate, admin=Depends(get_current_admin)):
    db["product"].update_one({"sku": sku}, {"$set": {"stock": payload.stock, "updated_at": datetime.now(timezone.utc)}})
    return {"status": "updated"}


# Orders admin
@app.get("/admin/orders")
def admin_list_orders(status: Optional[OrderStatus] = None, q: Optional[str] = None, admin=Depends(get_current_admin)):
    query = {}
    if status:
        query["status"] = status
    if q:
        query["$or"] = [
            {"customer.full_name": {"$regex": q, "$options": "i"}},
            {"customer.phone": {"$regex": q, "$options": "i"}},
        ]
    items = list(db["order"].find(query))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


class StatusChange(BaseModel):
    status: OrderStatus


@app.put("/admin/orders/{order_id}/status")
def admin_change_status(order_id: str, payload: StatusChange, admin=Depends(get_current_admin)):
    from bson import ObjectId
    try:
        oid = ObjectId(order_id)
    except Exception:
        raise HTTPException(404, "Order not found")
    db["order"].update_one({"_id": oid}, {"$set": {"status": payload.status, "updated_at": datetime.now(timezone.utc)}})
    return {"status": "updated"}


# Export CSV
@app.get("/admin/orders/export")
def admin_export_orders(admin=Depends(get_current_admin)):
    import csv
    from io import StringIO
    items = list(db["order"].find({}))
    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["order_id", "status", "total", "customer", "phone"])
    for it in items:
        writer.writerow([str(it.get("_id")), it.get("status"), it.get("total"), it.get("customer", {}).get("full_name"), it.get("customer", {}).get("phone")])
    return {"csv": out.getvalue()}


# Mock payment endpoint
@app.post("/payments/mock")
def mock_payment(amount: float):
    pid = f"pay_{int(datetime.now().timestamp())}"
    return {"payment_id": pid, "status": "success"}


# Simple health and db test
@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {"backend": "ok", "db": "ok", "collections": collections}
    except Exception as e:
        return {"backend": "ok", "db": f"error: {str(e)}"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
