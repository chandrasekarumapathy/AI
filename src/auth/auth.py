"""Password auth for the BigSleep dashboard.

- Admin password hashed with bcrypt (falls back to hashlib on missing bcrypt)
- Session tokens stored in memory (single-node; fine for company testing)
- FastAPI dependency: require_auth
- Dashboard login page served at /login
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Dict, Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

_AUTH_FILE = Path("config/auth.json")
_SESSION_TTL = 8 * 3600        # 8-hour sessions
_sessions: Dict[str, float] = {}   # token -> expiry timestamp


# ── Password storage ──────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except ImportError:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return f"pbkdf2:{salt}:{digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        import bcrypt
        if stored.startswith("$2"):
            return bcrypt.checkpw(password.encode(), stored.encode())
    except ImportError:
        pass
    if stored.startswith("pbkdf2:"):
        _, salt, expected = stored.split(":", 2)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return hmac.compare_digest(digest.hex(), expected)
    return False


def set_admin_password(password: str) -> None:
    """Hash and persist the admin password."""
    _AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if _AUTH_FILE.exists():
        data = json.loads(_AUTH_FILE.read_text())
    data["admin_hash"] = _hash_password(password)
    _AUTH_FILE.write_text(json.dumps(data, indent=2))


def check_admin_password(password: str) -> bool:
    if not _AUTH_FILE.exists():
        return False
    data = json.loads(_AUTH_FILE.read_text())
    stored = data.get("admin_hash", "")
    return bool(stored) and _verify_password(password, stored)


def is_password_set() -> bool:
    if not _AUTH_FILE.exists():
        return False
    data = json.loads(_AUTH_FILE.read_text())
    return bool(data.get("admin_hash"))


# ── Session management ────────────────────────────────────────────────────────

def create_session() -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + _SESSION_TTL
    _prune_sessions()
    return token


def validate_session(token: Optional[str]) -> bool:
    if not token:
        return False
    expiry = _sessions.get(token)
    if expiry and time.time() < expiry:
        _sessions[token] = time.time() + _SESSION_TTL  # rolling window
        return True
    _sessions.pop(token, None)
    return False


def invalidate_session(token: str) -> None:
    _sessions.pop(token, None)


def _prune_sessions() -> None:
    now = time.time()
    expired = [t for t, exp in _sessions.items() if now >= exp]
    for t in expired:
        del _sessions[t]


# ── FastAPI dependency ────────────────────────────────────────────────────────

def require_auth(
    request: Request,
    bs_session: Optional[str] = Cookie(default=None),
) -> str:
    if validate_session(bs_session):
        return bs_session
    raise HTTPException(
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={"Location": f"/login?next={request.url.path}"},
    )


# ── Login page HTML ───────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>BigSleep — Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 min-h-screen flex items-center justify-center">
  <div class="w-full max-w-sm bg-gray-900 border border-gray-700 rounded-2xl p-8 shadow-2xl">
    <div class="flex items-center gap-3 mb-8">
      <div class="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center text-white font-bold text-xl">B</div>
      <div>
        <h1 class="text-white font-bold text-lg">BigSleep ASM</h1>
        <p class="text-gray-500 text-xs">AI Attack Surface Management</p>
      </div>
    </div>
    {error_block}
    <form method="POST" action="/login" class="space-y-4">
      <input type="hidden" name="next" value="{next_url}" />
      <div>
        <label class="text-xs text-gray-400 block mb-1">Admin Password</label>
        <input name="password" type="password" autofocus required
               class="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2.5
                      text-white text-sm focus:outline-none focus:border-indigo-500" />
      </div>
      <button type="submit"
              class="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 rounded-lg
                     text-white text-sm font-medium transition">
        Sign In
      </button>
    </form>
    <p class="text-center text-xs text-gray-600 mt-6">
      BigSleep v1.0 &mdash; Authorised use only
    </p>
  </div>
</body>
</html>"""
