"""
MongoDB client for user authentication.
Handles user registration, login verification, JWT tokens,
and password reset token management.
"""

import os
import re
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient
from jose import jwt, JWTError

# ── Config ────────────────────────────────────────────────────────────────────
JWT_ALGO            = "HS256"
JWT_EXPIRES         = 24    # hours
RESET_TOKEN_EXPIRES = 30    # minutes

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
    return "mongodb+srv://" in uri or ".mongodb.net" in uri


# ── Client ────────────────────────────────────────────────────────────────────

class MongoAuthClient:

    def __init__(self):
        self.client        = None
        self.db            = None
        self.users         = None
        self.reset_tokens  = None   # separate collection for reset tokens
        self._connected    = False

    async def connect(self):
        mongo_uri = os.getenv("MONGO_URI", "").strip()

        if not mongo_uri:
            print("⚠️  MONGO_URI not set in .env — user auth will not work")
            return

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
                )

            await self.client.admin.command("ping")

            self.db           = self.client["intrusense"]
            self.users        = self.db["users"]
            self.reset_tokens = self.db["reset_tokens"]

            await self.users.create_index("email", unique=True)

            # TTL index — MongoDB auto-deletes expired reset tokens
            await self.reset_tokens.create_index(
                "expires_at",
                expireAfterSeconds=0
            )

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
            self.client        = None
            self.db            = None
            self.users         = None
            self.reset_tokens  = None
            self._connected    = False

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

    # ── Password reset ────────────────────────────────────────────────────────

    async def create_reset_token(self, email: str) -> Optional[str]:
        """
        Generate a secure reset token for the given email.
        Stores it in the reset_tokens collection with a 30-minute expiry.
        Returns the token string, or None if the email is not registered.
        """
        if not self.is_connected():
            return None

        # Verify the email exists before issuing a token
        user = await self.users.find_one({"email": email.lower().strip()})
        if not user:
            # Return None silently — the endpoint will still return 200
            # to avoid leaking which emails are registered
            return None

        if user.get("auth_provider") == "google":
            # Google accounts have no password to reset
            return None

        # Delete any existing unused token for this email
        await self.reset_tokens.delete_many({"email": email.lower().strip()})

        # Generate a cryptographically secure token
        token = secrets.token_urlsafe(32)

        await self.reset_tokens.insert_one({
            "email":      email.lower().strip(),
            "token":      token,
            "expires_at": datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRES),
            "used":       False
        })

        return token

    async def verify_reset_token(self, token: str) -> Optional[str]:
        """
        Verify a reset token is valid, not expired, and not used.
        Returns the associated email if valid, None otherwise.
        """
        if not self.is_connected():
            return None

        record = await self.reset_tokens.find_one({
            "token": token,
            "used":  False
        })

        if not record:
            return None

        if datetime.utcnow() > record["expires_at"]:
            await self.reset_tokens.delete_one({"token": token})
            return None

        return record["email"]

    async def reset_password(self, token: str, new_password: str) -> dict:
        """
        Reset a user's password using a valid reset token.
        Marks the token as used immediately to prevent reuse.
        """
        if not self.is_connected():
            return {"success": False, "error": "Database not connected"}

        # Validate the token
        email = await self.verify_reset_token(token)
        if not email:
            return {"success": False, "error": "Invalid or expired reset link. Please request a new one."}

        # Validate the new password strength
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            return {"success": False, "error": error_msg}

        # Mark token as used immediately — single use only
        await self.reset_tokens.update_one(
            {"token": token},
            {"$set": {"used": True}}
        )

        # Update the password
        try:
            await self.users.update_one(
                {"email": email},
                {"$set": {"password_hash": self.hash_password(new_password)}}
            )
            return {"success": True, "email": email}
        except Exception as e:
            print(f"❌ reset_password DB error: {e}")
            return {"success": False, "error": "Password reset failed. Please try again."}

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