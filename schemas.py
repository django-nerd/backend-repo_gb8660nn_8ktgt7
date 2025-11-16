"""
Database Schemas for Mini-Flipkart

Each Pydantic model represents a MongoDB collection. Collection name is the lowercase
class name (e.g., Product -> "product").
"""
from __future__ import annotations
from typing import List, Optional, Dict
from pydantic import BaseModel, Field, EmailStr
from enum import Enum


class Role(str, Enum):
    admin = "admin"


class AdminUser(BaseModel):
    username: str = Field(..., min_length=3)
    password_hash: str
    role: Role = Role.admin
    is_active: bool = True


class StockItem(BaseModel):
    size: str
    color: str
    quantity: int = Field(ge=0)


class Product(BaseModel):
    name: str
    sku: str
    description: Optional[str] = None
    price: float = Field(ge=0)
    sale_price: Optional[float] = Field(default=None, ge=0)
    categories: List[str] = []
    tags: List[str] = []
    sizes: List[str] = []
    colors: List[str] = []
    stock: List[StockItem] = []
    images: List[str] = []
    active: bool = True


class OrderItem(BaseModel):
    product_id: str
    name: str
    sku: str
    price: float
    color: Optional[str] = None
    size: Optional[str] = None
    quantity: int = Field(ge=1)
    image: Optional[str] = None


class OrderStatus(str, Enum):
    pending = "Pending"
    processing = "Processing"
    shipped = "Shipped"
    delivered = "Delivered"
    cancelled = "Cancelled"


class Address(BaseModel):
    full_name: str
    address: str
    city: str
    postal_code: str
    phone: str
    alt_phone: Optional[str] = None
    note: Optional[str] = None


class Order(BaseModel):
    items: List[OrderItem]
    customer: Address
    subtotal: float = Field(ge=0)
    taxes: float = Field(ge=0)
    shipping: float = Field(ge=0)
    total: float = Field(ge=0)
    status: OrderStatus = OrderStatus.pending
    payment_id: Optional[str] = None
    payment_status: str = "mocked"  # for mock payments


# Minimal analytics storage (optional per order)
class Event(BaseModel):
    type: str
    meta: Dict[str, str] = {}
