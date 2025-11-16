Backend (FastAPI) for Mini-Flipkart

- Auth with JWT (admin only)
- Products public catalog
- Orders create and manage
- MongoDB persistence

Environment variables:
- SECRET_KEY
- DATABASE_URL
- DATABASE_NAME

Run locally:
- pip install -r requirements.txt
- uvicorn main:app --reload --port 8000
