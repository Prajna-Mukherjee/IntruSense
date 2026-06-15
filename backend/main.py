from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

import os
import json
import io
import secrets
import pandas as pd
import httpx
from datetime import datetime, timedelta
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException, Header, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

from services.prediction_service import PredictionService
from services.shap_service import SHAPService
from services.mitre_service import MITREService
from database.elasticsearch_client import ElasticsearchClient
from database.mongo_client import MongoAuthClient
from websocket.websocket_server import ConnectionManager

# ── Config ────────────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
FRONTEND_URL         = os.getenv("FRONTEND_URL", "http://localhost:3000")
MAIL_USERNAME        = os.getenv("MAIL_USERNAME", "")
MAIL_PASSWORD        = os.getenv("MAIL_PASSWORD", "")

# ── Upload limits ─────────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_CSV_ROWS     = 5_000

# ── Allowed origins ───────────────────────────────────────────────────────────
_raw_origins    = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Mail config ───────────────────────────────────────────────────────────────
mail_config = ConnectionConfig(
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD,
    MAIL_FROM=MAIL_USERNAME,
    MAIL_FROM_NAME="IntruSense NIDS",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)
fast_mail = FastMail(mail_config) if MAIL_USERNAME and MAIL_PASSWORD else None

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="IntruSense AI Threat Detection Platform", version="2.0.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["Content-Length"],
    max_age=600,
)

# ── Services ──────────────────────────────────────────────────────────────────
prediction_service = PredictionService()
shap_service       = SHAPService(prediction_service)
mitre_service      = MITREService()
es_client          = ElasticsearchClient()
mongo_client       = MongoAuthClient()
manager            = ConnectionManager()

# ── One-time OAuth code store ─────────────────────────────────────────────────
_oauth_codes: dict = {}

def _create_oauth_code(token: str, name: str) -> str:
    code = secrets.token_urlsafe(32)
    _oauth_codes[code] = {
        "token":      token,
        "name":       name,
        "expires_at": datetime.utcnow() + timedelta(seconds=60)
    }
    return code

def _redeem_oauth_code(code: str) -> Optional[dict]:
    entry = _oauth_codes.pop(code, None)
    if not entry:
        return None
    if datetime.utcnow() > entry["expires_at"]:
        return None
    return entry

# ── Bulk delete confirmation token store ──────────────────────────────────────
_delete_confirm_tokens: dict = {}

def _issue_delete_token(user_email: str) -> str:
    token = secrets.token_urlsafe(32)
    _delete_confirm_tokens[token] = {
        "user_email": user_email,
        "expires_at": datetime.utcnow() + timedelta(seconds=60)
    }
    return token

def _redeem_delete_token(token: str, user_email: str) -> bool:
    entry = _delete_confirm_tokens.pop(token, None)
    if not entry:
        return False
    if datetime.utcnow() > entry["expires_at"]:
        return False
    if entry["user_email"] != user_email:
        return False
    return True

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    await es_client.create_index()
    await mongo_client.connect()
    print("✅ Platform started. Models loaded.")
    print(f"🌐 CORS allowed origins: {ALLOWED_ORIGINS}")
    if not GOOGLE_CLIENT_ID:
        print("⚠️  GOOGLE_CLIENT_ID not set — Google OAuth disabled")
    if not MAIL_USERNAME:
        print("⚠️  MAIL_USERNAME not set — password reset emails disabled")

# ── JWT helpers ───────────────────────────────────────────────────────────────
def get_user_email(authorization: str = "") -> str:
    if not authorization or not authorization.startswith("Bearer "):
        return ""
    token   = authorization[len("Bearer "):]
    payload = mongo_client.decode_token(token)
    return payload.get("sub", "") if payload else ""

def get_user_email_from_token(token: str) -> str:
    if not token:
        return ""
    payload = mongo_client.decode_token(token)
    return payload.get("sub", "") if payload else ""

def require_auth(authorization: str) -> str:
    user_email = get_user_email(authorization)
    if not user_email:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please provide a valid Bearer token."
        )
    return user_email

# ── Email helper ──────────────────────────────────────────────────────────────
async def send_reset_email(email: str, reset_token: str):
    """Send a password reset email with the reset link."""
    reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"

    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;
                background: #0a0e1a; color: #e2e8f0; padding: 40px; border-radius: 12px;">

        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #00d4ff; font-size: 28px; margin: 0;">🛡️ IntruSense</h1>
            <p style="color: #64748b; font-size: 12px; letter-spacing: 2px;">
                AI-POWERED NETWORK INTRUSION DETECTION SYSTEM
            </p>
        </div>

        <h2 style="color: #e2e8f0; font-size: 20px;">Password Reset Request</h2>

        <p style="color: #94a3b8; line-height: 1.6;">
            We received a request to reset the password for your IntruSense account
            associated with this email address.
        </p>

        <p style="color: #94a3b8; line-height: 1.6;">
            Click the button below to reset your password. This link will expire in
            <strong style="color: #00d4ff;">30 minutes</strong>.
        </p>

        <div style="text-align: center; margin: 35px 0;">
            <a href="{reset_link}"
               style="background: linear-gradient(135deg, #0284c7, #2563eb, #7c3aed);
                      color: #ffffff; padding: 14px 32px; border-radius: 8px;
                      text-decoration: none; font-weight: bold; font-size: 15px;
                      letter-spacing: 1px; display: inline-block;">
                RESET MY PASSWORD
            </a>
        </div>

        <p style="color: #64748b; font-size: 13px; line-height: 1.6;">
            If the button does not work, copy and paste this link into your browser:
            <br/>
            <a href="{reset_link}" style="color: #00d4ff; word-break: break-all;">
                {reset_link}
            </a>
        </p>

        <hr style="border: none; border-top: 1px solid #1e3a5f; margin: 30px 0;" />

        <p style="color: #475569; font-size: 12px; text-align: center;">
            If you did not request a password reset, ignore this email —
            your password will remain unchanged.
            <br/><br/>
            © 2026 IntruSense AI NIDS. All rights reserved.
        </p>
    </div>
    """

    message = MessageSchema(
        subject="IntruSense — Password Reset Request",
        recipients=[email],
        body=html_body,
        subtype=MessageType.html
    )

    await fast_mail.send_message(message)

# ── Request models ────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email:    EmailStr
    password: str
    name:     str

    @field_validator("name")
    @classmethod
    def name_must_not_be_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name must not be blank.")
        if len(v) > 100:
            raise ValueError("Name must be 100 characters or fewer.")
        return v

    @field_validator("email")
    @classmethod
    def email_must_not_be_too_long(cls, v: str) -> str:
        if len(v) > 254:
            raise ValueError("Email address is too long.")
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def password_must_not_be_blank(cls, v: str) -> str:
        if not v:
            raise ValueError("Password must not be blank.")
        return v


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def password_must_not_be_blank(cls, v: str) -> str:
        if not v:
            raise ValueError("Password must not be blank.")
        return v


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.lower().strip()


class ResetPasswordRequest(BaseModel):
    token:    str
    password: str

    @field_validator("password")
    @classmethod
    def password_must_not_be_blank(cls, v: str) -> str:
        if not v:
            raise ValueError("Password must not be blank.")
        return v

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.post("/auth/register")
@limiter.limit("10/hour")
async def register(request: Request, req: RegisterRequest):
    result = await mongo_client.register_user(req.email, req.password, req.name)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return {"token": result["token"], "name": result["name"]}

@app.post("/auth/login")
@limiter.limit("20/minute;100/hour")
async def login(request: Request, req: LoginRequest):
    result = await mongo_client.login_user(req.email, req.password)
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["error"])
    return {"token": result["token"], "name": result["name"]}

@app.get("/auth/google")
@limiter.limit("20/minute")
async def auth_google(request: Request):
    if not GOOGLE_CLIENT_ID:
        return JSONResponse({"error": "GOOGLE_CLIENT_ID not configured in .env"}, status_code=500)
    return RedirectResponse(
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&access_type=offline"
        f"&prompt=select_account"
    )

@app.get("/auth/google/callback")
@limiter.limit("20/minute")
async def auth_google_callback(request: Request, code: str):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")

    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code":          code,
                "client_id":     GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri":  GOOGLE_REDIRECT_URI,
                "grant_type":    "authorization_code"
            }
        )
        token_data   = token_res.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to get access token from Google")

        userinfo_res = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        userinfo = userinfo_res.json()

    email = userinfo.get("email", "")
    name  = userinfo.get("name", email.split("@")[0])
    if not email:
        raise HTTPException(status_code=400, detail="Could not get email from Google")

    result = await mongo_client.get_or_create_google_user(email, name)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["error"])

    oauth_code = _create_oauth_code(result["token"], name)
    return RedirectResponse(f"{FRONTEND_URL}/auth/callback?code={oauth_code}")

@app.get("/auth/exchange")
@limiter.limit("20/minute")
async def exchange_oauth_code(request: Request, code: str):
    entry = _redeem_oauth_code(code)
    if not entry:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OAuth code. Please sign in again."
        )
    return {"token": entry["token"], "name": entry["name"]}

@app.post("/auth/forgot-password")
@limiter.limit("5/hour")
async def forgot_password(request: Request, req: ForgotPasswordRequest):
    """
    Step 1 of password reset.
    Always returns 200 regardless of whether the email exists —
    this prevents attackers from enumerating registered emails.
    """
    reset_token = await mongo_client.create_reset_token(req.email)

    if reset_token and fast_mail:
        try:
            await send_reset_email(req.email, reset_token)
        except Exception as e:
            print(f"❌ Failed to send reset email: {e}")
            # Still return 200 — don't leak mail config errors to client

    # Always return the same response whether email exists or not
    return {
        "message": "If that email is registered you will receive a password reset link shortly."
    }

@app.post("/auth/reset-password")
@limiter.limit("10/hour")
async def reset_password(request: Request, req: ResetPasswordRequest):
    """
    Step 2 of password reset.
    Validates the token and updates the password.
    """
    result = await mongo_client.reset_password(req.token, req.password)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return {"message": "Password reset successfully. You can now log in with your new password."}

@app.get("/auth/verify-reset-token")
@limiter.limit("20/minute")
async def verify_reset_token(request: Request, token: str):
    """
    Called by the frontend Reset Password page on load to verify
    the token is still valid before showing the new password form.
    """
    email = await mongo_client.verify_reset_token(token)
    if not email:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset link. Please request a new one."
        )
    return {"valid": True}

# ── Core API routes ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"message": "IntruSense AI Threat Detection Platform"}

@app.get("/health")
@limiter.limit("30/minute")
async def health(request: Request):
    return {
        "status": "ok",
        "models": prediction_service.models_loaded(),
        "mongo":  mongo_client.is_connected()
    }

@app.post("/api/analyze")
@limiter.limit("30/minute;200/hour")
async def analyze_log(
    request:       Request,
    file:          UploadFile = File(...),
    authorization: Optional[str] = Header(default="")
):
    user_email = require_auth(authorization)

    chunks = []
    total  = 0
    while True:
        chunk = await file.read(1024 * 64)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024*1024)} MB."
            )
        chunks.append(chunk)

    contents = b"".join(chunks)

    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid CSV file. Could not parse.")

    if len(df) > MAX_CSV_ROWS:
        raise HTTPException(
            status_code=400,
            detail=f"CSV has too many rows ({len(df)}). Maximum allowed is {MAX_CSV_ROWS} rows per upload."
        )

    if len(df) == 0:
        raise HTTPException(status_code=400, detail="CSV file is empty.")

    results = []
    for _, row in df.iterrows():
        result = await process_single_log(row.to_dict(), user_email)
        results.append(result)

    return {
        "total":            len(results),
        "threats_detected": sum(1 for r in results if r["is_threat"]),
        "results":          results
    }

@app.post("/api/analyze/single")
@limiter.limit("60/minute")
async def analyze_single(
    request:       Request,
    log_data:      dict,
    authorization: Optional[str] = Header(default="")
):
    user_email = require_auth(authorization)
    return await process_single_log(log_data, user_email)

@app.get("/api/logs")
@limiter.limit("60/minute")
async def get_logs(
    request:       Request,
    size:          int = 50,
    authorization: Optional[str] = Header(default="")
):
    user_email = require_auth(authorization)
    logs = await es_client.get_recent_logs(size, user_email)
    return {"logs": logs}

@app.get("/api/stats")
@limiter.limit("60/minute")
async def get_stats(
    request:       Request,
    authorization: Optional[str] = Header(default="")
):
    user_email = require_auth(authorization)
    return await es_client.get_stats(user_email)

# ── Delete routes ─────────────────────────────────────────────────────────────
@app.delete("/api/logs/{log_id}")
@limiter.limit("60/minute")
async def delete_single_log(
    request:       Request,
    log_id:        str,
    es_id:         Optional[str] = None,
    authorization: Optional[str] = Header(default="")
):
    user_email = require_auth(authorization)
    success    = await es_client.delete_log(
        log_id=log_id, es_id=es_id or "", user_email=user_email
    )
    if not success:
        raise HTTPException(status_code=404, detail="Log not found or could not be deleted")
    return {"success": True, "deleted": log_id}

@app.post("/api/logs/delete-confirm")
@limiter.limit("10/minute")
async def request_delete_confirmation(
    request:       Request,
    authorization: Optional[str] = Header(default="")
):
    user_email    = require_auth(authorization)
    confirm_token = _issue_delete_token(user_email)
    return {
        "confirm_token": confirm_token,
        "expires_in":    60,
        "message":       "Pass this token as ?confirm_token= to DELETE /api/logs within 60 seconds."
    }

@app.delete("/api/logs")
@limiter.limit("5/minute")
async def delete_all_logs(
    request:       Request,
    confirm_token: Optional[str] = Query(default=None),
    authorization: Optional[str] = Header(default="")
):
    user_email = require_auth(authorization)

    if not confirm_token:
        raise HTTPException(
            status_code=400,
            detail=(
                "Bulk delete requires a confirmation token. "
                "First call POST /api/logs/delete-confirm to obtain one."
            )
        )

    if not _redeem_delete_token(confirm_token, user_email):
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired confirmation token. Please request a new one."
        )

    deleted = await es_client.delete_all_logs(user_email)
    return {"success": True, "deleted_count": deleted}

# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token:     Optional[str] = Query(default=None)
):
    user_email = get_user_email_from_token(token or "")
    if not user_email:
        await websocket.close(code=4001, reason="Unauthorized: valid token required")
        return

    await manager.connect(websocket, user_email)
    try:
        while True:
            data     = await websocket.receive_text()
            log_data = json.loads(data)
            result   = await process_single_log(log_data, user_email)
            await manager.send_personal_message(json.dumps(result), websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_email)

# ── Core processing pipeline ──────────────────────────────────────────────────
async def process_single_log(log_data: dict, user_email: str = "") -> dict:
    if "attack_type" in log_data and "label" not in log_data:
        log_data["label"] = log_data.pop("attack_type")
    if "difficulty_level" in log_data and "difficulty" not in log_data:
        log_data["difficulty"] = log_data.pop("difficulty_level")

    prediction  = prediction_service.predict(log_data)
    shap_values = shap_service.explain(log_data)
    mitre_info  = mitre_service.map_attack(prediction["attack_type"])

    result = {
        "log_data":     log_data,
        "is_threat":    prediction["is_threat"],
        "attack_type":  prediction["attack_type"],
        "threat_score": prediction["threat_score"],
        "confidence":   prediction["confidence"],
        "shap_values":  shap_values,
        "mitre":        mitre_info,
        "timestamp":    pd.Timestamp.now().isoformat()
    }

    await es_client.index_log(result, user_email)

    if prediction["is_threat"]:
        await manager.broadcast(
            json.dumps({"type": "THREAT_ALERT", "data": result}),
            user_email=user_email
        )

    return result