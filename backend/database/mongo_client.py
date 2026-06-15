"""
MongoDB client for user authentication.
Handles user registration, login verification, and JWT tokens.

Supports both:
  - Local MongoDB: mongodb://localhost:27017/intrusense  (no TLS)
  - MongoDB Atlas: mongodb+srv://...                     (TLS required)

The connection mode is detected automatically from MONGO_URI in .env.
"""

import os
import re
import bcrypt
from datetime import datetime, timedelta
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient
from jose import jwt, JWTError

# ── Config ────────────────────────────────────────────────────────────────────
JWT_ALGO    = "HS256"
JWT_EXPIRES = 24  # hours

# ── Common passwords blocklist ────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "password1", "password123", "password1234",
    "12345678", "123456789", "1234567890", "111111111",
    "iloveyou", "sunshine", "princess", "superman", "batman",
    "welcome1", "monkey123", "dragon123", "master123",
    "letmein1", "admin123", "root1234", "toor1234",
    "qwerty123", "qwertyui", "abc12345", "abcdefgh",
    "pass1234", "test1234", "user1234", "guest123",
    "intrusense", "intrusense1", "intrusense123",
}


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength. Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    if len(password) > 128:
        return False, "Password must be no more than 128 characters."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;':\",./<>?`~\\]", password):
        return False, "Password must contain at least one special character (!@#$%^&* etc)."

    if password.lower() in COMMON_PASSWORDS:
        return False, "This password is too common. Please choose a more unique password."

    return True, ""


def _is_atlas_uri(uri: str) -> bool:
    """
    Returns True if the URI is a MongoDB Atlas connection string.
    Atlas URIs use the +srv scheme or contain .mongodb.net
    Local URIs look like mongodb://localhost:27017
    """
    return "mongodb+srv://" in uri or ".mongodb.net" in uri


# ── Client ────────────────────────────────────────────────────────────────────

class MongoAuthClient:

    def __init__(self):
        self.client     = None
        self.db         = None
        self.users      = None
        self._connected = False

    async def connect(self):
        mongo_uri = os.getenv("MONGO_URI", "").strip()

        if not mongo_uri:
            print("⚠️  MONGO_URI not set in .env — user auth will not work")
            return

        # ── FIX: Detect connection type and set TLS accordingly ───────────────
        # Local MongoDB does not use TLS — forcing tls=True on a local
        # connection causes an immediate connection failure.
        # Atlas always requires TLS.
        is_atlas = _is_atlas_uri(mongo_uri)

        try:
            if is_atlas:
                print("🌐 Connecting to MongoDB Atlas...")
                self.client = AsyncIOMotorClient(
                    mongo_uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=10000,
                    tls=True,
                    tlsAllowInvalidCertificates=False
                )
            else:
                print("🍃 Connecting to local MongoDB...")
                self.client = AsyncIOMotorClient(
                    mongo_uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=10000
                    # No TLS for local instance
                )

            # Force an actual network round-trip to verify connection
            await self.client.admin.command("ping")

            self.db    = self.client["intrusense"]
            self.users = self.db["users"]

            # Ensure unique index on email
            await self.users.create_index("email", unique=True)

            self._connected = True
            mode = "Atlas" if is_atlas else "local"
            print(f"✅ MongoDB connected ({mode}) — user auth ready")

        except Exception as e:
            print(f"❌ MongoDB connection failed: {e}")
            if is_atlas:
                print("   → Check: 1) MONGO_URI in .env  2) Atlas IP whitelist  3) DB user password")
            else:
                print("   → Check: 1) MongoDB is running: sudo systemctl status mongod")
                print("             2) MONGO_URI in .env is: mongodb://localhost:27017/intrusense")
            self.client     = None
            self.db         = None
            self.users      = None
            self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    # ── Password helpers ──────────────────────────────────────────────────────

    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

    def verify_password(self, plain: str, hashed: str) -> bool:
        return bcrypt.checkpw(
            plain.encode("utf-8"),
            hashed.encode("utf-8")
        )

    # ── JWT helpers ───────────────────────────────────────────────────────────

    def _jwt_secret(self) -> str:
        secret = os.getenv("JWT_SECRET", "").strip()

        if not secret:
            raise RuntimeError(
                "JWT_SECRET is not set in your .env file. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        if len(secret) < 32:
            raise RuntimeError(
                f"JWT_SECRET is too short ({len(secret)} chars). "
                "It must be at least 32 characters. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        return secret

    def create_token(self, email: str, name: str) -> str:
        payload = {
            "sub":  email,
            "name": name,
            "exp":  datetime.utcnow() + timedelta(hours=JWT_EXPIRES)
        }
        return jwt.encode(payload, self._jwt_secret(), algorithm=JWT_ALGO)

    def decode_token(self, token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, self._jwt_secret(), algorithms=[JWT_ALGO])
        except JWTError:
            return None

    # ── User operations ───────────────────────────────────────────────────────

    async def register_user(self, email: str, password: str, name: str) -> dict:
        if not self.is_connected():
            return {"success": False, "error": "Database not connected"}

        existing = await self.users.find_one({"email": email.lower().strip()})
        if existing:
            return {"success": False, "error": "Email already registered"}

        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return {"success": False, "error": error_msg}

        user_doc = {
            "email":         email.lower().strip(),
            "password_hash": self.hash_password(password),
            "name":          name.strip(),
            "role":          "analyst",
            "created_at":    datetime.utcnow().isoformat(),
            "auth_provider": "email"
        }

        try:
            await self.users.insert_one(user_doc)
            token = self.create_token(email.lower(), name)
            return {"success": True, "token": token, "name": name}
        except Exception as e:
            print(f"❌ register_user DB error: {e}")
            return {"success": False, "error": "Registration failed due to a server error. Please try again."}

    async def login_user(self, email: str, password: str) -> dict:
        if not self.is_connected():
            return {"success": False, "error": "Database not connected"}

        user = await self.users.find_one({"email": email.lower().strip()})

        if not user:
            return {"success": False, "error": "Invalid email or password"}

        if user.get("auth_provider") == "google":
            return {"success": False, "error": "This account uses Google Sign-In. Please use the Google button."}

        if not self.verify_password(password, user["password_hash"]):
            return {"success": False, "error": "Invalid email or password"}

        token = self.create_token(user["email"], user["name"])
        return {"success": True, "token": token, "name": user["name"]}

    async def get_or_create_google_user(self, email: str, name: str) -> dict:
        if not self.is_connected():
            return {"success": False, "error": "Database not connected"}

        user = await self.users.find_one({"email": email.lower()})

        if not user:
            user_doc = {
                "email":         email.lower(),
                "password_hash": "",
                "name":          name,
                "role":          "analyst",
                "created_at":    datetime.utcnow().isoformat(),
                "auth_provider": "google"
            }
            await self.users.insert_one(user_doc)

        token = self.create_token(email.lower(), name)
        return {"success": True, "token": token, "name": name}