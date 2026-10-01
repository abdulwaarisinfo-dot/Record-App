"""
Sales Record App  -  FastAPI + MongoDB + Jinja2
Run:  uvicorn index:app --reload
Install:  pip install fastapi "uvicorn[standard]" motor jinja2 python-multipart itsdangerous python-dotenv httpx

Env vars (optional):
  MONGO_URL       default mongodb://localhost:27017
  DB_NAME         default sales_db
  SECRET_KEY      session signing key (change in production!)
  ADMIN_EMAIL     first user, created automatically   default admin@example.com
  ADMIN_PASSWORD  first user's password               default admin123
  PING_URL        public URL to ping (Render sets RENDER_EXTERNAL_URL automatically)
  PING_INTERVAL   seconds between pings                default 20
"""
import asyncio
import hashlib
import hmac
import os
import secrets
from contextlib import asynccontextmanager
from datetime import date

import httpx
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

load_dotenv()  # reads the .env file

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "sales_db")
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
PING_URL = (os.getenv("PING_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").rstrip("/")
PING_INTERVAL = int(os.getenv("PING_INTERVAL", "20"))

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]
users = db["users"]
records = db["records"]
templates = Jinja2Templates(directory="templates")


# ---------- password helpers ----------
def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


# ---------- keep-alive ping ----------
async def keep_alive():
    """Pings this server's own public URL so the host does not put it to sleep."""
    if not PING_URL:
        return  # running locally, nothing to ping
    async with httpx.AsyncClient(timeout=10) as http:
        while True:
            await asyncio.sleep(PING_INTERVAL)
            try:
                await http.get(f"{PING_URL}/ping")
            except Exception:
                pass  # ignore; try again on the next round


# ---------- startup ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    await users.create_index("email", unique=True)
    await records.create_index("bill_number", unique=True)
    if not await users.find_one({"email": ADMIN_EMAIL}):
        await users.insert_one({"email": ADMIN_EMAIL, "password": hash_password(ADMIN_PASSWORD)})
    ping_task = asyncio.create_task(keep_alive())
    yield
    ping_task.cancel()
    client.close()


app = FastAPI(title="Sales Records", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=60 * 60 * 12)


# ---------- models ----------
class SaleIn(BaseModel):
    date: date
    bill_number: str = Field(min_length=1, max_length=40)
    quality: str = Field(min_length=1, max_length=80)
    quantity: float = Field(gt=0)
    rate: float = Field(ge=0)


def serialize(doc: dict, sr: int | None = None) -> dict:
    return {
        "id": str(doc["_id"]),
        "sr": sr,
        "date": doc["date"],
        "bill_number": doc["bill_number"],
        "quality": doc["quality"],
        "quantity": doc["quantity"],
        "rate": doc["rate"],
        "total_amount": doc["total_amount"],
    }


def require_login(request: Request):
    if not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Login required")


def to_doc(data: SaleIn) -> dict:
    return {
        "date": data.date.isoformat(),
        "bill_number": data.bill_number.strip(),
        "quality": data.quality.strip(),
        "quantity": data.quantity,
        "rate": data.rate,
        "total_amount": round(data.quantity * data.rate, 2),
    }


def oid(record_id: str) -> ObjectId:
    if not ObjectId.is_valid(record_id):
        raise HTTPException(status_code=404, detail="Record not found")
    return ObjectId(record_id)


# ---------- pages ----------
@app.api_route("/ping", methods=["GET", "HEAD"])
async def ping():
    return {"status": "ok"}


@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(
        request, "record.html", {"logged_in": bool(request.session.get("email")),
                                 "email": request.session.get("email", ""),
                                 "error": request.session.pop("error", None)}
    )


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    user = await users.find_one({"email": email})
    # Both email AND password must be correct, otherwise login fails
    if user and verify_password(password, user["password"]):
        request.session["email"] = user["email"]
    else:
        request.session["error"] = "Email or password is incorrect."
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


# ---------- records API ----------
@app.get("/api/records")
async def list_records(request: Request):
    require_login(request)
    # Oldest first, so the Sr. number follows the order of entry
    docs = await records.find().sort([("date", 1), ("_id", 1)]).to_list(None)
    return [serialize(d, i) for i, d in enumerate(docs, start=1)]


@app.get("/api/next-bill")
async def next_bill(request: Request):
    require_login(request)
    last = await records.find().sort("_id", -1).limit(1).to_list(1)
    if not last:
        return {"bill_number": "1001"}
    b = last[0]["bill_number"]
    return {"bill_number": str(int(b) + 1) if b.isdigit() else ""}


@app.post("/api/records", status_code=201)
async def add_record(request: Request, data: SaleIn):
    require_login(request)
    doc = to_doc(data)
    if await records.find_one({"bill_number": doc["bill_number"]}):
        raise HTTPException(status_code=409, detail="This bill number already exists.")
    res = await records.insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize(doc)


@app.put("/api/records/{record_id}")
async def update_record(request: Request, record_id: str, data: SaleIn):
    require_login(request)
    doc = to_doc(data)
    clash = await records.find_one({"bill_number": doc["bill_number"], "_id": {"$ne": oid(record_id)}})
    if clash:
        raise HTTPException(status_code=409, detail="This bill number already exists.")
    res = await records.find_one_and_update({"_id": oid(record_id)}, {"$set": doc}, return_document=True)
    if not res:
        raise HTTPException(status_code=404, detail="Record not found")
    return serialize(res)


@app.delete("/api/records/{record_id}")
async def delete_record(request: Request, record_id: str):
    require_login(request)
    res = await records.delete_one({"_id": oid(record_id)})
    if not res.deleted_count:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"ok": True}
