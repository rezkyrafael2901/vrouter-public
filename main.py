"""
VRouter Public API — JEROUTER-style LLM provider platform.
- Email OTP authentication
- API key generation
- Proxy to VRouter backend (port 20129)
- Dashboard with model listing + usage stats
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import secrets
import smtplib
import sqlite3
import string
import time
from collections import deque
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


# Password hashing (bcrypt-style via hashlib for simplicity)
import hashlib as _hl

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = _hl.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + ":" + h.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        check = _hl.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return check.hex() == h
    except Exception:
        return False

# ═══════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════
BASE_DIR = Path(__file__).parent
DB_PATH = os.environ.get("PUB_DB_PATH", str(BASE_DIR / "public.db"))
VROUTER_URL = os.environ.get("VROUTER_URL", "http://127.0.0.1:20129")
VROUTER_KEY = os.environ.get("VROUTER_KEY", "")  # internal Bearer
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
PORT = int(os.environ.get("PUB_PORT", "20130"))
SITE_NAME = os.environ.get("SITE_NAME", "VRouter")
SITE_TAGLINE = os.environ.get("SITE_TAGLINE", "One API. Every model.")
SITE_URL = os.environ.get("SITE_URL", "https://vrouter.my.id")
OTP_EXPIRY_SECONDS = 300  # 5 min
MAX_OTP_ATTEMPTS = 3

# Google OAuth2
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "https://vrouter.my.id/auth/google/callback")
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# ═══════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            api_key TEXT DEFAULT '',
            password_hash TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_requests INTEGER DEFAULT 0,
            total_tokens_in INTEGER DEFAULT 0,
            total_tokens_out INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            attempts INTEGER DEFAULT 0,
            used INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS usage_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            model TEXT,
            provider TEXT DEFAULT '',
            tokens_in INTEGER DEFAULT 0,
            tokens_out INTEGER DEFAULT 0,
            cached_tokens INTEGER DEFAULT 0,
            cache_creation_tokens INTEGER DEFAULT 0,
            latency_ms INTEGER DEFAULT 0,
            ttft_ms INTEGER DEFAULT 0,
            status TEXT DEFAULT 'ok',
            request_json TEXT,
            response_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_key ON users(api_key);
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            key TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT 'Default',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_apikeys_key ON api_keys(key);
        CREATE INDEX IF NOT EXISTS idx_apikeys_user ON api_keys(user_id);
    """)
    conn.close()
    # Migration: add role column if missing (older DBs)
    try:
        conn = sqlite3.connect(DB_PATH)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "role" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Migration] role column: {e}")
    # One-time migration: move existing users.api_key into api_keys table
    try:
        _migrate_api_keys()
    except Exception as e:
        print(f"[Migration] skipped: {e}")
    # Migration: add enhanced usage_log columns
    try:
        conn = sqlite3.connect(DB_PATH)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(usage_log)").fetchall()]
        for col_name, col_type, col_default in [
            ("provider", "TEXT", "''"),
            ("cached_tokens", "INTEGER", "0"),
            ("cache_creation_tokens", "INTEGER", "0"),
            ("ttft_ms", "INTEGER", "0"),
            ("request_json", "TEXT", None),
            ("response_json", "TEXT", None),
        ]:
            if col_name not in cols:
                default_clause = f" DEFAULT {col_default}" if col_default is not None else ""
                conn.execute(f"ALTER TABLE usage_log ADD COLUMN {col_name} {col_type}{default_clause}")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Migration] usage_log columns: {e}")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

_oauth_states: dict = {}  # state -> timestamp (server-side CSRF store)

def _migrate_api_keys():
    """Move single api_key from users table into api_keys table (one-time migration)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    existing = conn.execute("SELECT COUNT(*) as c FROM api_keys").fetchone()["c"]
    if existing > 0:
        conn.close()
        return
    users = conn.execute("SELECT id, api_key FROM users WHERE api_key != '' AND api_key IS NOT NULL").fetchall()
    for u in users:
        conn.execute(
            "INSERT INTO api_keys (user_id, key, name) VALUES (?, ?, ?)",
            (u["id"], u["api_key"], "Default")
        )
    conn.commit()
    conn.close()
    print(f"[Migration] Moved {len(users)} API keys to api_keys table")
# ═══════════════════════════════════════════════════════════════════
# EMAIL OTP
# ═══════════════════════════════════════════════════════════════════
def generate_otp() -> str:
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email: str, code: str) -> bool:
    msg = MIMEText(f"""
Your verification code is: {code}

This code expires in 5 minutes.
If you didn't request this, ignore this email.

— {SITE_NAME}
    """, "plain")
    msg["Subject"] = f"[{SITE_NAME}] Your verification code: {code}"
    msg["From"] = f"{SITE_NAME} <{SMTP_USER}>"
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[SMTP ERROR] {e}")
        return False

# ═══════════════════════════════════════════════════════════════════
# API KEY HELPERS
# ═══════════════════════════════════════════════════════════════════
def generate_api_key() -> str:
    return "vr-" + secrets.token_hex(24)


def hash_api_key(key: str) -> str:
    """SHA-256 hash of an API key — stored in DB instead of plaintext."""
    return hashlib.sha256(key.encode()).hexdigest()


def mask_key(key: str) -> str:
    """vr-xxxx...yyyy"""
    if len(key) > 12:
        return key[:7] + "..." + key[-4:]
    return key[:7] + "..."

# ═══════════════════════════════════════════════════════════════════
# USAGE STATS (in-memory + DB)
# ═══════════════════════════════════════════════════════════════════
USAGE_BUFFER: deque = deque(maxlen=200)
TOTAL_REQUESTS = 0
START_TIME = time.time()

def log_usage(email: str, model: str, tokens_in: int, tokens_out: int, latency_ms: int, status: str = "ok",
              provider: str = "", cached_tokens: int = 0, cache_creation_tokens: int = 0,
              ttft_ms: int = 0, request_json: str = None, response_json: str = None):
    global TOTAL_REQUESTS
    TOTAL_REQUESTS += 1
    entry = {
        "email": email, "model": model, "tokens_in": tokens_in,
        "tokens_out": tokens_out, "latency_ms": latency_ms,
        "status": status, "time": time.time()
    }
    USAGE_BUFFER.append(entry)
    # persist to DB
    try:
        db = get_db()
        db.execute(
            "INSERT INTO usage_log (email,model,provider,tokens_in,tokens_out,cached_tokens,cache_creation_tokens,latency_ms,ttft_ms,status,request_json,response_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (email, model, provider, tokens_in, tokens_out, cached_tokens, cache_creation_tokens, latency_ms, ttft_ms, status, request_json, response_json)
        )
        db.execute(
            "UPDATE users SET total_requests=total_requests+1, total_tokens_in=total_tokens_in+?, total_tokens_out=total_tokens_out+? WHERE email=?",
            (tokens_in, tokens_out, email)
        )
        db.commit()
        db.close()
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════
# VROUTER PROXY
# ═══════════════════════════════════════════════════════════════════
http_client: Optional[httpx.AsyncClient] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient(
        base_url=VROUTER_URL,
        headers={"Authorization": f"Bearer {VROUTER_KEY}"},
        timeout=httpx.Timeout(60.0, connect=10.0),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )
    init_db()
    print(f"[VRouter Public] Started on port {PORT}, proxying to {VROUTER_URL}")
    yield
    await http_client.aclose()

app = FastAPI(title="VRouter Public API", lifespan=lifespan, redirect_slashes=False, docs_url="/api-docs", redoc_url="/api-redoc")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to every response."""
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Serve static files (logo, etc.)
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ═══════════════════════════════════════════════════════════════════
# AUTH MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════
async def verify_api_key(request: Request) -> str:
    """Extract and validate API key, return email."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        key = auth[7:].strip()
    else:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header. Use: Authorization: Bearer <key>")

    db = get_db()
    row = db.execute("""
        SELECT u.email, u.is_active
        FROM api_keys ak
        JOIN users u ON ak.user_id = u.id
        WHERE ak.key=? AND ak.is_active=1
    """, (hash_api_key(key),)).fetchone()
    db.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not row["is_active"]:
        raise HTTPException(status_code=403, detail="Account deactivated")
    return row["email"]

# ═══════════════════════════════════════════════════════════════════
# PUBLIC ROUTES (no auth)
# ═══════════════════════════════════════════════════════════════════
def get_user_context(request: Request) -> dict:
    """Check login cookies and return user context for templates."""
    email = request.cookies.get("vrouter_email")
    session_id = request.cookies.get("vrouter_session")
    if email and session_id:
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email=? AND id=?", (email, session_id)).fetchone()
        db.close()
        if user:
            return {"is_logged_in": True, "user_email": email, "user_initial": email[0].upper()}
    return {"is_logged_in": False, "user_email": "", "user_initial": ""}


@app.get("/", response_class=HTMLResponse)
async def root_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "landing.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        **ctx,
    })


@app.get("/landing", response_class=HTMLResponse)
async def landing_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "landing.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        **ctx,
    })


@app.get("/docs", response_class=HTMLResponse)
async def docs_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "docs.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        **ctx,
    })


@app.get("/features", response_class=HTMLResponse)
async def features_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "landing.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        "scroll_to": "features",
        **ctx,
    })


@app.get("/how", response_class=HTMLResponse)
async def how_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "landing.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        "scroll_to": "how-it-works",
        **ctx,
    })


@app.get("/pricing", response_class=HTMLResponse)
async def pricing_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "landing.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        "scroll_to": "pricing",
        **ctx,
    })


@app.get("/faq", response_class=HTMLResponse)
async def faq_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "landing.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        "scroll_to": "faq",
        **ctx,
    })


@app.get("/font-test", response_class=HTMLResponse)
async def font_test_page(request: Request):
    return templates.TemplateResponse(request, "font-test.html", {})


@app.get("/font-compare", response_class=HTMLResponse)
async def font_compare_page(request: Request):
    return templates.TemplateResponse(request, "font-compare.html", {})


@app.get("/font-compare-v2", response_class=HTMLResponse)
async def font_compare_v2_page(request: Request):
    return templates.TemplateResponse(request, "font-compare-v2.html", {})


@app.get("/status", response_class=HTMLResponse)
async def status_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "status.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        **ctx,
    })


@app.get("/terms", response_class=HTMLResponse)
async def terms_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "terms.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        **ctx,
    })


@app.get("/fair-use", response_class=HTMLResponse)
async def fair_use_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "fair_use.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        **ctx,
    })


@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request):
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "privacy.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        **ctx,
    })


@app.get("/integrations", response_class=HTMLResponse)
async def integrations_page(request: Request):
    """Auth-gated integrations page."""
    email = request.cookies.get("vrouter_email")
    session_id = request.cookies.get("vrouter_session")
    if not email or not session_id:
        from starlette.responses import RedirectResponse
        return RedirectResponse(url="/auth", status_code=302)

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()

    if not user:
        from starlette.responses import RedirectResponse
        return RedirectResponse(url="/auth", status_code=302)

    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "integrations.html", {
        "site_name": SITE_NAME,
        "site_tagline": SITE_TAGLINE,
        "site_url": SITE_URL,
        **ctx,
    })



@app.get("/models", response_class=HTMLResponse)
async def models_page(request: Request):
    """Public models listing page."""
    db = get_db()
    rows = db.execute(
        "SELECT model_id, display_name, provider, enabled, tier, hidden FROM models_config WHERE enabled=1 AND hidden=0 ORDER BY sort_order, model_id"
    ).fetchall()
    db.close()
    
    models = []
    for r in rows:
        models.append({
            "model_id": r[0],
            "display_name": r[1] or r[0],
            "provider": r[2] or "",
            "enabled": bool(r[3]),
            "tier": r[4] or "free",
            "hidden": bool(r[5]),
        })
    
    ctx = get_user_context(request)
    return templates.TemplateResponse(request, "models.html", {
        "site_name": SITE_NAME,
        "site_url": SITE_URL,
        "models": models,
        **ctx,
    })

@app.get("/auth", response_class=HTMLResponse)
async def auth_page(request: Request):
    return templates.TemplateResponse(request, "auth.html", {
        "site_name": SITE_NAME,
        "site_url": SITE_URL,
    })


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


@app.get("/robots.txt", response_class=Response)
async def robots_txt():
    content = f"""User-agent: *
Allow: /
Disallow: /admin
Disallow: /dashboard
Disallow: /auth

Sitemap: {SITE_URL}/sitemap.xml
"""
    return Response(content=content, media_type="text/plain")


@app.get("/sitemap.xml", response_class=Response)
async def sitemap_xml():
    content = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{SITE_URL}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>{SITE_URL}/docs</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>{SITE_URL}/features</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>{SITE_URL}/pricing</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>{SITE_URL}/faq</loc><changefreq>monthly</changefreq><priority>0.6</priority></url>
  <url><loc>{SITE_URL}/models</loc><changefreq>weekly</changefreq><priority>0.6</priority></url>
  <url><loc>{SITE_URL}/status</loc><changefreq>daily</changefreq><priority>0.5</priority></url>
  <url><loc>{SITE_URL}/terms</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>{SITE_URL}/privacy</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
</urlset>
"""
    return Response(content=content, media_type="application/xml")


# ═══════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════
# PASSWORD-BASED AUTH (Madefaka-style)
# ═══════════════════════════════════════════════════════════════════
@app.post("/auth/register")
async def register_email(request: Request):
    """Register with email + password."""
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    
    if not email or "@" not in email:
        raise HTTPException(400, "Invalid email")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        db.close()
        raise HTTPException(409, "Email already registered")
    
    pw_hash = hash_password(password)
    db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash))
    db.commit()
    user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    db.close()
    
    # Set cookies and redirect to dashboard
    from starlette.responses import RedirectResponse
    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.set_cookie("vrouter_session", str(user["id"]), httponly=True, max_age=86400 * 365, samesite="lax")
    resp.set_cookie("vrouter_email", email, httponly=True, max_age=86400 * 365, samesite="lax")
    return resp


@app.post("/auth/login")
async def login_email(request: Request):
    """Login with email + password."""
    # Try JSON first, then form data
    try:
        body = await request.json()
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
    except Exception:
        form = await request.form()
        email = (form.get("email") or "").strip().lower()
        password = form.get("password") or ""
    
    if not email or not password:
        raise HTTPException(400, "Email and password required")
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()
    
    if not user:
        raise HTTPException(401, "Invalid credentials")
    
    # Check password (if set)
    if user["password_hash"]:
        if not verify_password(password, user["password_hash"]):
            raise HTTPException(401, "Invalid credentials")
    
    from starlette.responses import RedirectResponse
    next_url = request.query_params.get("next", "/dashboard")
    # Prevent redirect loops
    if next_url.startswith("/auth") or not next_url.startswith("/"):
        next_url = "/dashboard"
    resp = RedirectResponse(url=next_url, status_code=302)
    resp.set_cookie("vrouter_session", str(user["id"]), httponly=True, max_age=86400 * 365, samesite="lax")
    resp.set_cookie("vrouter_email", email, httponly=True, max_age=86400 * 365, samesite="lax")
    return resp


@app.get("/auth/logout")
async def logout():
    """Clear cookies and redirect to home."""
    from starlette.responses import RedirectResponse
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("vrouter_key")
    resp.delete_cookie("vrouter_email")
    return resp

# GOOGLE OAUTH2
# ═══════════════════════════════════════════════════════════════════


@app.get("/dashboard", response_class=HTMLResponse)
async def user_dashboard(request: Request):
    """Dashboard — shows API keys, usage stats, model access."""
    email = request.cookies.get("vrouter_email")
    session_id = request.cookies.get("vrouter_session")
    if not email or not session_id:
        return RedirectResponse(url="/auth", status_code=302)
    
    # Get user stats from DB
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=? AND id=?", (email, session_id)).fetchone()
    
    api_keys = []
    if user:
        keys_rows = db.execute(
            "SELECT id, key, name, created_at, is_active FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
            (user["id"],)
        ).fetchall()
        api_keys = [dict(k) for k in keys_rows]
        for k in api_keys:
            # Hash stored — mask from hash
            k["masked"] = (k["key"][:8] + "..." + k["key"][-4:]) if len(k["key"]) > 12 else (k["key"][:7] + "...")
            del k["key"]
    db.close()
    
    stats = {}
    if user:
        stats = {
            "email": user["email"],
            "has_keys": len(api_keys) > 0,
            "total_requests": user["total_requests"],
            "tokens_in": user["total_tokens_in"],
            "tokens_out": user["total_tokens_out"],
            "full_name": user["full_name"] or "",
            "username": user["username"] or "",
            "avatar_url": user["avatar_url"] or "",
            "is_admin": user["is_admin"] or 0,
        }
    else:
        # User cookie exists but not in DB — force re-login
        return RedirectResponse(url="/auth", status_code=302)
    
    # Get available models
    # Fetch models from VRouter backend, filter hidden/disabled
    try:
        r = await http_client.get("/v1/models")
        models_data = r.json().get("data", [])
        # Filter by models_config: skip hidden and disabled
        db2 = get_db()
        cfg_rows = db2.execute("SELECT model_id, hidden, enabled, display_name FROM models_config").fetchall()
        cfg_map = {r["model_id"]: dict(r) for r in cfg_rows}
        db2.close()
        models_resp = []
        for m in models_data:
            mid = m.get("id", "")
            if not mid:
                continue
            c = cfg_map.get(mid)
            if c and (c.get("hidden") or not c.get("enabled")):
                continue
            display = ""
            if c and c.get("display_name"):
                display = c["display_name"]
            models_resp.append({"id": mid, "display_name": display, "provider": mid.split("/")[0] if "/" in mid else "direct", "tier": m.get("tier", "free")})
    except Exception as e:
        print(f"[Dashboard] models fetch error: {e}")
        models_resp = []
    
    return templates.TemplateResponse(request, "dashboard_user.html", {
        "site_name": SITE_NAME,
        "site_url": SITE_URL,
        "stats": stats,
        "api_keys": api_keys,
        "models": models_resp[:50],  # Top 50 models
        "model_count": len(models_resp),
        "is_admin": stats.get("is_admin", 0) if stats else 0,
    })

@app.get("/auth/google")
async def google_oauth_redirect(request: Request):
    """Redirect user to Google OAuth consent screen."""
    scope = "openid email profile"
    state = secrets.token_urlsafe(16)
    # Store state in session/cookie for CSRF protection
    # Store state server-side (cookie gets lost on mobile OAuth redirect)
    _oauth_states[state] = time.time()
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": scope,
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    url = GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return Response(content="", status_code=302, headers={"Location": url})


@app.get("/auth/google/callback")
async def google_oauth_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """Handle Google OAuth callback — exchange code for tokens, get user info."""
    # Verify state against server-side store
    if not state or state not in _oauth_states:
        raise HTTPException(400, "Invalid OAuth state — CSRF protection")
    # Clean up used state + expired states
    now = time.time()
    _oauth_states.pop(state, None)
    expired = [s for s, t in _oauth_states.items() if now - t > 600]
    for s in expired:
        _oauth_states.pop(s, None)
    
    if error:
        raise HTTPException(400, f"Google OAuth error: {error}")
    
    if not code:
        raise HTTPException(400, "Missing authorization code")
    
    # Exchange code for access token
    token_data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": GOOGLE_REDIRECT_URI,
    }
    
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(GOOGLE_TOKEN_URL, data=token_data)
        if token_resp.status_code != 200:
            raise HTTPException(500, f"Failed to exchange code for token: {token_resp.text}")
        token_json = token_resp.json()
        
        access_token = token_json.get("access_token")
        if not access_token:
            raise HTTPException(500, "No access token in response")
        
        # Get user info from Google
        user_resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_resp.status_code != 200:
            raise HTTPException(500, f"Failed to get user info: {user_resp.text}")
        user_info = user_resp.json()
    
    email = user_info.get("email", "").strip().lower()
    if not email:
        raise HTTPException(400, "No email in Google user info")
    
    # Check if user exists, create if not
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        db.execute("INSERT INTO users (email) VALUES (?)", (email,))
        db.commit()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()
    
    # Set auth cookies and redirect to dashboard
    from starlette.responses import RedirectResponse
    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.set_cookie("vrouter_session", str(user["id"]), httponly=True, max_age=86400 * 365, samesite="lax")
    resp.set_cookie("vrouter_email", email, httponly=True, max_age=86400 * 365, samesite="lax")
    return resp


# ─── OTP FLOW ───
# Rate-limit state (per-email cooldown + per-IP budget)
_otp_email_last: dict[str, float] = {}
_otp_ip_hits: dict[str, list[float]] = {}
OTP_EMAIL_COOLDOWN_S = 60
OTP_IP_MAX_PER_HOUR = 10


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.post("/auth/request-otp")
async def request_otp(request: Request):
    body = await request.json()
    email = (body.get("email") or "").strip().lower()

    if not email or "@" not in email:
        raise HTTPException(400, "Valid email required")

    # Per-IP budget: max 10 requests/hour
    ip = _client_ip(request)
    now = time.time()
    hits = [t for t in _otp_ip_hits.get(ip, []) if now - t < 3600]
    if len(hits) >= OTP_IP_MAX_PER_HOUR:
        raise HTTPException(429, "Too many OTP requests from this IP. Try again later.")
    hits.append(now)
    _otp_ip_hits[ip] = hits

    # Per-email cooldown: 60s between codes to same email
    last = _otp_email_last.get(email, 0)
    if now - last < OTP_EMAIL_COOLDOWN_S:
        raise HTTPException(429, "Please wait a minute before requesting another code.")

    code = generate_otp()
    db = get_db()

    # Rate limit: max 3 OTPs per email per 10 min
    recent = db.execute(
        "SELECT COUNT(*) as cnt FROM otps WHERE email=? AND created_at > datetime('now', '-10 minutes')",
        (email,)
    ).fetchone()["cnt"]
    if recent >= 3:
        db.close()
        raise HTTPException(429, "Too many OTP requests. Wait 10 minutes.")

    db.execute("INSERT INTO otps (email, code) VALUES (?, ?)", (email, code))
    db.commit()
    db.close()
    _otp_email_last[email] = now

    ok = send_otp_email(email, code)
    if not ok:
        raise HTTPException(500, "Failed to send email. Try again.")

    return {"ok": True, "message": f"Code sent to {email}"}

@app.post("/auth/verify-otp")
async def verify_otp(request: Request):
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    code = (body.get("code") or "").strip()

    if not email or not code:
        raise HTTPException(400, "Email and code required")

    db = get_db()
    otp = db.execute(
        "SELECT * FROM otps WHERE email=? AND code=? AND used=0 ORDER BY id DESC LIMIT 1",
        (email, code)
    ).fetchone()

    if not otp:
        db.close()
        raise HTTPException(400, "Invalid or expired code")

    if otp["attempts"] >= MAX_OTP_ATTEMPTS:
        db.execute("UPDATE otps SET used=1 WHERE id=?", (otp["id"],))
        db.commit()
        db.close()
        raise HTTPException(429, "Too many attempts. Request a new code.")

    # Check expiry
    otp_time = datetime.fromisoformat(otp["created_at"])
    if datetime.utcnow() - otp_time > timedelta(seconds=OTP_EXPIRY_SECONDS):
        db.execute("UPDATE otps SET used=1 WHERE id=?", (otp["id"],))
        db.commit()
        db.close()
        raise HTTPException(400, "Code expired. Request a new one.")

    # Mark OTP used
    db.execute("UPDATE otps SET used=1 WHERE id=?", (otp["id"],))

    # Check if user exists
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        db.execute("INSERT INTO users (email) VALUES (?)", (email,))

    db.commit()
    db.close()

    return {
        "ok": True,
        "api_key": "",
        "email": email,
        "message": "Account verified. Create an API key from your dashboard."
    }

# ─── MODELS LISTING ───
@app.get("/v1/models")
async def list_models():
    """Public model listing — filtered by models_config."""
    try:
        resp = await http_client.get("/v1/models")
        data = resp.json()
        backend_models = data.get("data", [])
        
        # Get config
        db = get_db()
        config_rows = db.execute("SELECT model_id, enabled, tier, hidden, display_name FROM models_config").fetchall()
        config = {r["model_id"]: dict(r) for r in config_rows}
        db.close()
        
        public_models = []
        for m in backend_models:
            mid = m.get("id", "")
            if not mid:
                continue
            cfg = config.get(mid)
            # If no config entry: show by default (enabled, free)
            if cfg:
                if not cfg["enabled"] or cfg.get("hidden"):
                    continue
                tier = cfg["tier"]
            else:
                tier = "free"
            
            display = cfg["display_name"] if cfg and cfg.get("display_name") else (
                mid.split("/")[-1].upper().replace("-", " ") if "/" in mid else mid.upper().replace("-", " ")
            )
            public_models.append({
                "id": mid,
                "name": display,
                "provider": mid.split("/")[0] if "/" in mid else "direct",
                "tier": tier,
            })
        
        return {"data": public_models, "object": "list", "total": len(public_models)}
    except Exception as e:
        return {"data": [], "object": "list", "total": 0, "error": str(e)}

# ─── HEALTH ───
@app.get("/health")
async def health():
    try:
        resp = await http_client.get("/v1/models")
        vrouter_ok = resp.status_code == 200
    except Exception:
        vrouter_ok = False

    db = get_db()
    user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    db.close()

    return {
        "status": "ok" if vrouter_ok else "degraded",
        "vrouter": "online" if vrouter_ok else "offline",
        "users": user_count,
        "uptime": int(time.time() - START_TIME),
        "total_requests": TOTAL_REQUESTS,
    }

# ═══════════════════════════════════════════════════════════════════
# API KEY MANAGEMENT (dashboard-authenticated)
# ═══════════════════════════════════════════════════════════════════
def _get_user_from_session(request: Request):
    """Get user from session cookie. Returns (user_row, db) or (None, None)."""
    email = request.cookies.get("vrouter_email")
    session_id = request.cookies.get("vrouter_session")
    if not email or not session_id:
        return None, None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=? AND id=?", (email, session_id)).fetchone()
    if not user:
        db.close()
        return None, None
    return user, db


@app.post("/api-keys")
async def create_api_key(request: Request):
    """Create a new API key for the logged-in user."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")
    
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    name = (body.get("name") or "Key").strip()[:64] or "Key"
    
    key = generate_api_key()
    db.execute(
        "INSERT INTO api_keys (user_id, key, name) VALUES (?, ?, ?)",
        (user["id"], hash_api_key(key), name)
    )
    db.commit()
    key_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.close()
    
    return {
        "ok": True,
        "key_id": key_id,
        "key": key,
        "name": name,
        "masked": key[:8] + "..." + key[-4:],
        "message": "Store this key securely. It won't be shown in full again."
    }


@app.delete("/api-keys/{key_id}")
async def delete_api_key(key_id: int, request: Request):
    """Delete an API key."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")
    
    # Only delete if it belongs to this user
    result = db.execute(
        "DELETE FROM api_keys WHERE id=? AND user_id=?",
        (key_id, user["id"])
    )
    db.commit()
    db.close()
    
    if result.rowcount == 0:
        raise HTTPException(404, "Key not found")
    
    return {"ok": True, "message": "Key deleted"}


@app.get("/api-keys")
async def list_api_keys(request: Request):
    """List all API keys for the logged-in user."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")
    
    rows = db.execute(
        "SELECT id, name, key, created_at, is_active FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
        (user["id"],)
    ).fetchall()
    db.close()
    
    keys = []
    for r in rows:
        k = dict(r)
        # Hash stored — mask from the hash itself
        k["masked"] = (k["key"][:8] + "..." + k["key"][-4:]) if len(k["key"]) > 12 else (k["key"][:7] + "...")
        del k["key"]  # Don't expose key (hash) in list
        keys.append(k)
    
    return {"ok": True, "keys": keys}


@app.get("/dashboard/usage-logs")
async def get_usage_logs(request: Request):
    """Get usage logs for the logged-in user with filters + pagination."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")
    
    # ─── Query params: period, provider, model, start, end, page, page_size ───
    period = request.query_params.get("period", "all")
    provider_filter = request.query_params.get("provider", "")
    model_filter = request.query_params.get("model", "")
    start_dt = request.query_params.get("start", "")
    end_dt = request.query_params.get("end", "")
    try:
        page = max(1, int(request.query_params.get("page", "1")))
    except Exception:
        page = 1
    try:
        page_size = min(200, max(1, int(request.query_params.get("page_size", "20"))))
    except Exception:
        page_size = 20
    
    where = ["email=?"]
    params = [user["email"]]
    
    if period == "today":
        where.append("date(created_at)=date('now','localtime')")
    elif period == "24h":
        where.append("created_at > datetime('now', '-24 hours')")
    elif period == "7d":
        where.append("created_at > datetime('now', '-7 days')")
    elif period == "30d":
        where.append("created_at > datetime('now', '-30 days')")
    elif period == "60d":
        where.append("created_at > datetime('now', '-60 days')")
    if start_dt:
        where.append("created_at >= ?")
        params.append(start_dt.replace("T", " ") + ":00")
    if end_dt:
        where.append("created_at <= ?")
        params.append(end_dt.replace("T", " ") + ":59")
    if provider_filter:
        where.append("provider LIKE ?")
        params.append(f"%{provider_filter}%")
    if model_filter:
        where.append("model = ?")
        params.append(model_filter)
    
    where_sql = " AND ".join(where)
    
    # Total count for pagination
    total = db.execute(
        f"SELECT COUNT(*) as c FROM usage_log WHERE {where_sql}", params
    ).fetchone()["c"]
    
    offset = (page - 1) * page_size
    logs = db.execute(
        f"""SELECT id, model, provider, tokens_in, tokens_out, cached_tokens,
                   cache_creation_tokens, latency_ms, ttft_ms, status, created_at
           FROM usage_log WHERE {where_sql}
           ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?""",
        params + [page_size, offset]
    ).fetchall()
    
    # Get summary stats
    summary = db.execute(
        f"""SELECT 
            COUNT(*) as total_requests,
            COALESCE(SUM(tokens_in), 0) as total_tokens_in,
            COALESCE(SUM(tokens_out), 0) as total_tokens_out,
            COALESCE(SUM(cached_tokens), 0) as total_cached_tokens,
            COALESCE(AVG(latency_ms), 0) as avg_latency,
            COALESCE(AVG(ttft_ms), 0) as avg_ttft
          FROM usage_log WHERE {where_sql}""",
        params
    ).fetchone()
    
    # Get last 24h stats
    last24 = db.execute(
        """SELECT 
            COUNT(*) as requests,
            COALESCE(SUM(tokens_in), 0) as tokens_in,
            COALESCE(SUM(tokens_out), 0) as tokens_out
          FROM usage_log WHERE email=? AND created_at > datetime('now', '-24 hours')""",
        (user["email"],)
    ).fetchone()
    
    # Get per-model breakdown
    models = db.execute(
        """SELECT model, COUNT(*) as requests, 
            COALESCE(SUM(tokens_in), 0) as tokens_in,
            COALESCE(SUM(tokens_out), 0) as tokens_out
          FROM usage_log WHERE email=? GROUP BY model ORDER BY requests DESC LIMIT 10""",
        (user["email"],)
    ).fetchall()

    # Get per-provider breakdown (with model-prefix fallback for legacy rows)
    providers = db.execute(
        """SELECT prov as provider, SUM(requests) as requests,
                  SUM(tokens_in) as tokens_in, SUM(tokens_out) as tokens_out
           FROM (
             SELECT
               CASE WHEN provider != '' THEN provider
                    WHEN model LIKE '%/%' THEN substr(model, 1, instr(model, '/') - 1)
                    ELSE '(unknown)' END as prov,
               COUNT(*) as requests,
               COALESCE(SUM(tokens_in), 0) as tokens_in,
               COALESCE(SUM(tokens_out), 0) as tokens_out
             FROM usage_log WHERE email=?
             GROUP BY prov
           ) GROUP BY prov ORDER BY requests DESC""",
        (user["email"],)
    ).fetchall()
    
    db.close()
    
    # Fill empty providers from model prefix (e.g. "openai/gpt-4o" -> "openai")
    processed_logs = []
    for lg in logs:
        lg_dict = dict(lg)
        if not lg_dict.get("provider") and lg_dict.get("model") and "/" in lg_dict["model"]:
            lg_dict["provider"] = lg_dict["model"].split("/", 1)[0]
        processed_logs.append(lg_dict)
    
    return {
        "ok": True,
        "logs": processed_logs,
        "summary": dict(summary) if summary else {},
        "last_24h": dict(last24) if last24 else {},
        "models": [dict(m) for m in models],
        "providers": [dict(p) for p in providers],
        "pagination": {"page": page, "page_size": page_size, "total": total, "pages": max(1, -(-total // page_size))}
    }


@app.get("/dashboard/usage-timeseries")
async def get_usage_timeseries(request: Request):
    """Get hourly usage time-series for the last 7 days."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")

    # Hourly breakdown for last 7 days
    hourly = db.execute(
        """SELECT
            strftime('%Y-%m-%d %H:00', created_at) as hour,
            COUNT(*) as requests,
            COALESCE(SUM(tokens_in), 0) as tokens_in,
            COALESCE(SUM(tokens_out), 0) as tokens_out
           FROM usage_log WHERE email=? AND created_at > datetime('now', '-7 days')
           GROUP BY hour ORDER BY hour""",
        (user["email"],)
    ).fetchall()

    # Daily breakdown for last 30 days
    daily = db.execute(
        """SELECT
            strftime('%Y-%m-%d', created_at) as day,
            COUNT(*) as requests,
            COALESCE(SUM(tokens_in), 0) as tokens_in,
            COALESCE(SUM(tokens_out), 0) as tokens_out
           FROM usage_log WHERE email=? AND created_at > datetime('now', '-30 days')
           GROUP BY day ORDER BY day""",
        (user["email"],)
    ).fetchall()

    db.close()

    return {
        "ok": True,
        "hourly": [dict(h) for h in hourly],
        "daily": [dict(d) for d in daily],
    }


@app.get("/dashboard/usage-detail")
async def get_usage_detail(request: Request):
    """Get full request/response detail for a single usage log entry."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")
    log_id = request.query_params.get("id", "")
    row = db.execute(
        "SELECT request_json, response_json FROM usage_log WHERE id=? AND email=?",
        (log_id, user["email"])
    ).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Log not found")
    return {"ok": True, "request": row["request_json"], "response": row["response_json"]}



# ═══════════════════════════════════════════════════════════════════
# PROFILE MANAGEMENT (dashboard-authenticated)
# ═══════════════════════════════════════════════════════════════════
@app.get("/profile")
async def get_profile(request: Request):
    """Get profile data for the logged-in user."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")
    db.close()
    return {
        "ok": True,
        "full_name": user["full_name"] or "",
        "username": user["username"] or "",
        "avatar_url": user["avatar_url"] or "",
        "email": user["email"],
    }


@app.put("/profile")
async def update_profile(request: Request):
    """Update profile (full_name, username)."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")

    body = await request.json()
    full_name = (body.get("full_name") or "").strip()[:100]
    username = (body.get("username") or "").strip()[:32]

    # Validate username: alphanumeric + underscore, unique
    if username:
        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            db.close()
            raise HTTPException(400, "Username must be alphanumeric (underscores allowed)")
        existing = db.execute(
            "SELECT id FROM users WHERE username=? AND id!=?",
            (username, user["id"])
        ).fetchone()
        if existing:
            db.close()
            raise HTTPException(400, "Username already taken")

    db.execute(
        "UPDATE users SET full_name=?, username=? WHERE id=?",
        (full_name, username, user["id"])
    )
    db.commit()
    db.close()
    return {"ok": True, "message": "Profile updated"}


@app.post("/profile/avatar")
async def upload_avatar(request: Request, file: UploadFile = File(...)):
    """Upload avatar image (base64 data URL stored in DB)."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")

    # Validate file type
    allowed = {"image/jpeg", "image/png", "image/gif", "image/webp"}
    if file.content_type not in allowed:
        db.close()
        raise HTTPException(400, "Only JPEG, PNG, GIF, WebP allowed")

    # Read and validate size (max 2MB)
    contents = await file.read()
    if len(contents) > 2 * 1024 * 1024:
        db.close()
        raise HTTPException(400, "Max 2MB")

    # Convert to base64 data URL
    b64 = base64.b64encode(contents).decode()
    data_url = f"data:{file.content_type};base64,{b64}"

    db.execute("UPDATE users SET avatar_url=? WHERE id=?", (data_url, user["id"]))
    db.commit()
    db.close()
    return {"ok": True, "avatar_url": data_url, "message": "Avatar updated"}


@app.delete("/profile/avatar")
async def delete_avatar(request: Request):
    """Remove avatar (reset to initial-based default)."""
    user, db = _get_user_from_session(request)
    if not user:
        raise HTTPException(401, "Not logged in")
    db.execute("UPDATE users SET avatar_url='' WHERE id=?", (user["id"],))
    db.commit()
    db.close()
    return {"ok": True, "message": "Avatar removed"}


# ═══════════════════════════════════════════════════════════════════
# PROTECTED ROUTES (API key required)
# ═══════════════════════════════════════════════════════════════════
@app.post("/v1/chat/completions")
async def chat_completions(request: Request, email: str = Depends(verify_api_key)):
    body = await request.json()
    model = body.get("model", "")
    start = time.time()

    # ─── MODEL ACCESS GATE: only allow enabled models from models_config ───
    if model:
        db_check = get_db()
        cfg = db_check.execute(
            "SELECT enabled, hidden FROM models_config WHERE model_id=?", (model,)
        ).fetchone()
        db_check.close()
        if cfg is None:
            raise HTTPException(
                400,
                detail={"error": {"message": f"Model '{model}' is not available. Use GET /v1/models to list available models.", "type": "invalid_request_error", "code": "model_not_found"}}
            )
        if not cfg["enabled"] or cfg["hidden"]:
            raise HTTPException(
                403,
                detail={"error": {"message": f"Model '{model}' is currently disabled.", "type": "invalid_request_error", "code": "model_disabled"}}
            )

    # Forward to VRouter
    is_stream = body.get("stream", False)

    try:
        if is_stream:
            req = http_client.build_request(
                "POST", "/v1/chat/completions",
                json=body,
                headers={"Accept": "text/event-stream"}
            )
            resp = await http_client.send(req, stream=True)

            if resp.status_code != 200:
                error_body = await resp.aread()
                await resp.aclose()
                try:
                    err = json.loads(error_body)
                except Exception:
                    err = {"detail": error_body.decode()[:500]}
                log_usage(email, model, 0, 0, int((time.time()-start)*1000), "error")
                raise HTTPException(resp.status_code, detail=err)

            async def stream_gen():
                tokens_out = 0
                tokens_in = len(json.dumps(body.get("messages", []))) // 4
                cached_tokens = 0
                cache_creation_tokens = 0
                provider = ""
                ttft_ms = 0
                first_content_seen = False
                resp_chunks = []
                try:
                    async for chunk in resp.aiter_bytes():
                        yield chunk
                        # Count approximate tokens from SSE data + capture usage/provider
                        try:
                            line = chunk.decode("utf-8", errors="ignore")
                            for l in line.split("\n"):
                                if l.startswith("data: ") and l.strip() != "data: [DONE]":
                                    d = json.loads(l[6:])
                                    if "choices" in d and d["choices"]:
                                        delta = d["choices"][0].get("delta", {})
                                        content = delta.get("content", "")
                                        if content:
                                            if not first_content_seen:
                                                first_content_seen = True
                                                ttft_ms = int((time.time() - start) * 1000)
                                            tokens_out += len(content) // 4
                                    # OpenAI-style usage chunk (stream_options include_usage)
                                    u = d.get("usage")
                                    if u:
                                        tokens_out = u.get("completion_tokens", tokens_out)
                                        if "prompt_tokens" in u:
                                            tokens_in = u.get("prompt_tokens", tokens_in)
                                        det = u.get("prompt_tokens_details") or {}
                                        cached_tokens = det.get("cached_tokens", u.get("cached_tokens", 0))
                                        cache_creation_tokens = det.get("cache_creation", u.get("cache_creation_input_tokens", 0))
                                    if not provider:
                                        provider = d.get("provider") or d.get("model", "").split("/")[0] if "/" in d.get("model", "") else ""
                                        if "usage" in str(d)[:80] and provider:
                                            pass
                                    resp_chunks.append(l[6:][:400])
                        except Exception:
                            pass
                finally:
                    latency = int((time.time() - start) * 1000)
                    if not provider:
                        provider = resp.headers.get("x-provider") or resp.headers.get("x-upstream-provider") or ""
                    log_usage(email, model, tokens_in, tokens_out, latency, "ok",
                              provider=provider, cached_tokens=cached_tokens,
                              cache_creation_tokens=cache_creation_tokens,
                              ttft_ms=ttft_ms,
                              request_json=json.dumps(body)[:4000],
                              response_json=" ".join(resp_chunks)[:4000])
                    await resp.aclose()

            return StreamingResponse(stream_gen(), media_type="text/event-stream")
        else:
            resp = await http_client.post("/v1/chat/completions", json=body)
            latency = int((time.time() - start) * 1000)
            data = resp.json()
            usage = data.get("usage", {})
            tokens_in = usage.get("prompt_tokens", 0)
            tokens_out = usage.get("completion_tokens", 0)
            det = usage.get("prompt_tokens_details") or {}
            cached_tokens = det.get("cached_tokens", usage.get("cached_tokens", 0))
            cache_creation_tokens = det.get("cache_creation", usage.get("cache_creation_input_tokens", 0))
            provider = data.get("provider") or resp.headers.get("x-provider") or resp.headers.get("x-upstream-provider") or ""
            ttft_ms = data.get("ttft_ms") or data.get("ttft") or 0
            log_usage(email, model, tokens_in, tokens_out, latency, "ok" if resp.status_code == 200 else "error",
                      provider=provider, cached_tokens=cached_tokens,
                      cache_creation_tokens=cache_creation_tokens,
                      ttft_ms=ttft_ms,
                      request_json=json.dumps(body)[:4000],
                      response_json=json.dumps(data)[:4000])
            return JSONResponse(content=data, status_code=resp.status_code)

    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(503, "VRouter backend unavailable")
    except Exception as e:
        log_usage(email, model, 0, 0, int((time.time()-start)*1000), "error")
        raise HTTPException(500, f"Proxy error: {str(e)[:200]}")

@app.get("/v1/usage")
async def get_usage(email: str = Depends(verify_api_key)):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    recent = db.execute(
        "SELECT model, COUNT(*) as requests, SUM(tokens_in) as tin, SUM(tokens_out) as tout FROM usage_log WHERE email=? AND created_at > datetime('now', '-24 hours') GROUP BY model ORDER BY requests DESC",
        (email,)
    ).fetchall()
    db.close()

    return {
        "email": email,
        "total_requests": user["total_requests"] if user else 0,
        "total_tokens_in": user["total_tokens_in"] if user else 0,
        "total_tokens_out": user["total_tokens_out"] if user else 0,
        "last_24h": [dict(r) for r in recent]
    }


# ═══════════════════════════════════════════════════════════════════
# ADMIN — MODEL MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

def require_admin(request: Request) -> str:
    """Dependency: current user must be admin. Returns email or raises 401/403."""
    email = request.cookies.get("vrouter_email")
    session_id = request.cookies.get("vrouter_session")
    if not email or not session_id:
        raise HTTPException(status_code=401, detail="Not logged in")
    db = get_db()
    user = db.execute("SELECT role, is_admin FROM users WHERE email=? AND id=?", (email, session_id)).fetchone()
    db.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")
    is_admin = (user["role"] == "admin") or (user["is_admin"] or 0) == 1
    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return email


# Backward-compat alias used by existing handlers
check_admin = require_admin


@app.get("/admin")
async def admin_page(request: Request):
    """Admin panel — model management."""
    email = request.cookies.get("vrouter_email")
    session_id = request.cookies.get("vrouter_session")
    if not email or not session_id:
        return RedirectResponse(url="/auth?next=/admin", status_code=302)
    db = get_db()
    user = db.execute("SELECT role, is_admin FROM users WHERE email=? AND id=?", (email, session_id)).fetchone()
    db.close()
    is_admin = user and ((user["role"] == "admin") or (user["is_admin"] or 0) == 1)
    if not is_admin:
        return RedirectResponse(url="/dashboard", status_code=302)
    resp = templates.TemplateResponse(request, "admin.html", {
        "site_name": SITE_NAME,
        "site_url": SITE_URL,
        "admin_email": email,
    })
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.get("/admin/api/models")
async def admin_list_models(request: Request):
    """List all models with config from models_config + VRouter backend."""
    check_admin(request)
    
    # Get models from VRouter backend
    backend_models = []
    try:
        resp = await http_client.get("/v1/models")
        data = resp.json()
        backend_models = data.get("data", [])
    except Exception as e:
        print(f"[Admin] Backend models fetch error: {e}")
    
    # Get config from DB
    db = get_db()
    config_rows = db.execute("SELECT * FROM models_config").fetchall()
    config = {r["model_id"]: dict(r) for r in config_rows}
    db.close()
    
    # Merge: backend models + config
    models = []
    seen = set()
    for m in backend_models:
        mid = m.get("id", "")
        if not mid or mid in seen:
            continue
        seen.add(mid)
        cfg = config.get(mid, {})
        # Skip hidden models
        if cfg.get("hidden"):
            continue
        models.append({
            "id": mid,
            "name": mid.split("/")[-1].upper().replace("-", " ") if "/" in mid else mid.upper().replace("-", " "),
            "provider": mid.split("/")[0] if "/" in mid else "direct",
            "enabled": cfg.get("enabled", 1),
            "tier": cfg.get("tier", "free"),
            "display_name": cfg.get("display_name", ""),
            "sort_order": cfg.get("sort_order", 0),
            "in_config": mid in config,
        })
    
    # Add config-only models (not in backend anymore)
    for mid, cfg in config.items():
        if mid not in seen:
            seen.add(mid)
            # Skip hidden models
            if cfg.get("hidden"):
                continue
            models.append({
                "id": mid,
                "name": cfg.get("display_name", mid.split("/")[-1].upper().replace("-", " ")),
                "provider": cfg.get("provider", "unknown"),
                "enabled": cfg.get("enabled", 0),
                "tier": cfg.get("tier", "disabled"),
                "display_name": cfg.get("display_name", ""),
                "sort_order": cfg.get("sort_order", 0),
                "in_config": True,
                "removed": True,
            })
    
    # Sort: enabled first, then by tier (free > pro), then by sort_order
    tier_order = {"free": 0, "pro": 1, "disabled": 2}
    models.sort(key=lambda x: (0 if x["enabled"] else 1, tier_order.get(x["tier"], 3), x["sort_order"]))
    
    return {"models": models, "total": len(models)}


@app.post("/admin/api/models/sync")
async def admin_sync_models(request: Request):
    """Auto-sync all backend models into models_config."""
    check_admin(request)
    
    # Fetch from backend
    try:
        resp = await http_client.get("/v1/models")
        data = resp.json()
        backend_models = data.get("data", [])
    except Exception as e:
        return {"ok": False, "error": str(e)}
    
    db = get_db()
    added = 0
    skipped = 0
    for m in backend_models:
        mid = m.get("id", "")
        if not mid:
            continue
        exists = db.execute("SELECT id FROM models_config WHERE model_id=?", (mid,)).fetchone()
        if exists:
            skipped += 1
            continue
        provider = mid.split("/")[0] if "/" in mid else "direct"
        display = mid.split("/")[-1].upper().replace("-", " ") if "/" in mid else mid.upper().replace("-", " ")
        db.execute(
            "INSERT INTO models_config (model_id, display_name, provider, enabled, tier, sort_order) VALUES (?, ?, ?, 1, 'free', ?)",
            (mid, display, provider, added)
        )
        added += 1
    db.commit()
    db.close()
    
    return {"ok": True, "added": added, "skipped": skipped, "total": len(backend_models)}


@app.put("/admin/api/models/update")
async def admin_update_model(request: Request):
    """Update a model's config (enabled, tier, display_name, sort_order, provider)."""
    check_admin(request)
    body = await request.json()
    model_id = body.get("model_id")
    
    db = get_db()
    exists = db.execute("SELECT id FROM models_config WHERE model_id=?", (model_id,)).fetchone()
    
    if exists:
        provider = body.get("provider", "")
        if provider:
            db.execute("""
                UPDATE models_config 
                SET enabled=?, tier=?, display_name=?, sort_order=?, hidden=?, provider=?, updated_at=datetime('now')
                WHERE model_id=?
            """, (
                body.get("enabled", 1),
                body.get("tier", "free"),
                body.get("display_name", ""),
                body.get("sort_order", 0),
                body.get("hidden", 0),
                provider,
                model_id
            ))
        else:
            db.execute("""
                UPDATE models_config 
                SET enabled=?, tier=?, display_name=?, sort_order=?, hidden=?, updated_at=datetime('now')
                WHERE model_id=?
            """, (
                body.get("enabled", 1),
                body.get("tier", "free"),
                body.get("display_name", ""),
                body.get("sort_order", 0),
                body.get("hidden", 0),
                model_id
            ))
    else:
        provider = body.get("provider", "") or (model_id.split("/")[0] if "/" in model_id else "direct")
        db.execute("""
            INSERT INTO models_config (model_id, display_name, provider, enabled, tier, sort_order)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            model_id,
            body.get("display_name", model_id.split("/")[-1].upper().replace("-", " ")),
            provider,
            body.get("enabled", 1),
            body.get("tier", "free"),
            body.get("sort_order", 0)
        ))
    
    db.commit()
    db.close()
    return {"ok": True}


@app.delete("/admin/api/models/delete")
async def admin_delete_model(request: Request):
    """Hide a model from admin listing."""
    check_admin(request)
    body = await request.json()
    model_id = body.get("model_id")
    if not model_id:
        return {"ok": False, "detail": "model_id required"}
    db = get_db()
    exists = db.execute("SELECT id FROM models_config WHERE model_id=?", (model_id,)).fetchone()
    if exists:
        db.execute("UPDATE models_config SET hidden=1, updated_at=datetime('now') WHERE model_id=?", (model_id,))
    else:
        provider = model_id.split("/")[0] if "/" in model_id else "direct"
        display = model_id.split("/")[-1].upper().replace("-", " ") if "/" in model_id else model_id.upper().replace("-", " ")
        db.execute(
            "INSERT INTO models_config (model_id, display_name, provider, enabled, tier, sort_order, hidden) VALUES (?, ?, ?, 0, 'disabled', 0, 1)",
            (model_id, display, provider)
        )
    db.commit()
    db.close()
    return {"ok": True}


@app.post("/admin/api/models/bulk")
async def admin_bulk_update(request: Request):
    """Bulk update multiple models at once."""
    check_admin(request)
    body = await request.json()
    updates = body.get("models", [])
    
    db = get_db()
    updated = 0
    for u in updates:
        mid = u.get("model_id")
        if not mid:
            continue
        exists = db.execute("SELECT id FROM models_config WHERE model_id=?", (mid,)).fetchone()
        if exists:
            db.execute("""
                UPDATE models_config SET enabled=?, tier=?, updated_at=datetime('now')
                WHERE model_id=?
            """, (u.get("enabled", 1), u.get("tier", "free"), mid))
        else:
            provider = mid.split("/")[0] if "/" in mid else "direct"
            db.execute("""
                INSERT INTO models_config (model_id, display_name, provider, enabled, tier, sort_order)
                VALUES (?, ?, ?, ?, ?, 0)
            """, (mid, mid.split("/")[-1].upper().replace("-", " "), provider, u.get("enabled", 1), u.get("tier", "free")))
        updated += 1
    db.commit()
    db.close()
    return {"ok": True, "updated": updated}


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")

