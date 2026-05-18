"""
Session-based authentication — multi-user with DB storage.
Admin credentials bootstrapped from SOC_USERNAME / SOC_PASSWORD env vars on first run.
Token cookie encodes username + timestamp + HMAC signature.
"""

import hashlib
import hmac
import os
import secrets
import time

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

_SECRET = os.environ.get("SOC_SECRET", "please-change-this-secret-key")
_COOKIE = "soc_token"
_TTL    = 60 * 60 * 12  # 12 hours

# Bootstrap admin credentials from env (used only to seed DB on first run)
_BOOTSTRAP_USER = os.environ.get("SOC_USERNAME", "admin")
_BOOTSTRAP_PASS = os.environ.get("SOC_PASSWORD", "changeme")


# ── Password helpers ──────────────────────────────────────────────────────────

def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def _new_salt() -> str:
    return secrets.token_hex(16)


# ── Token helpers ─────────────────────────────────────────────────────────────

def _sign(payload: str) -> str:
    return hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _make_token(username: str, is_admin: bool) -> str:
    ts = str(int(time.time()))
    role = "1" if is_admin else "0"
    payload = f"{username}:{role}:{ts}"
    sig = _sign(payload)
    return f"{payload}.{sig}"


def _verify_token(token: str) -> dict | None:
    """Returns {username, is_admin} if valid, else None."""
    try:
        body, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(body)):
            return None
        parts = body.split(":")
        if len(parts) != 3:
            return None
        username, role, ts = parts
        if (time.time() - int(ts)) >= _TTL:
            return None
        return {"username": username, "is_admin": role == "1"}
    except Exception:
        return None


# ── DB user management ────────────────────────────────────────────────────────

def _get_conn():
    from backend.db import get_conn
    return get_conn()


def bootstrap_admin() -> None:
    """Seed the admin user from env vars if no users exist yet."""
    conn = _get_conn()
    count = conn.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0]
    if count == 0:
        salt = _new_salt()
        pw_hash = _hash_password(_BOOTSTRAP_PASS, salt)
        conn.execute(
            "INSERT INTO auth_users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, TRUE)",
            [_BOOTSTRAP_USER, pw_hash, salt],
        )


def verify_credentials(username: str, password: str) -> dict | None:
    """Returns {username, is_admin} if valid, else None."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT username, password_hash, salt, is_admin FROM auth_users WHERE username = ?",
        [username],
    ).fetchone()
    if not row:
        return None
    db_user, pw_hash, salt, is_admin = row
    if hmac.compare_digest(pw_hash, _hash_password(password, salt)):
        return {"username": db_user, "is_admin": bool(is_admin)}
    return None


def list_users() -> list[dict]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT username, is_admin, created_at FROM auth_users ORDER BY created_at"
    ).fetchall()
    return [{"username": r[0], "is_admin": bool(r[1]), "created_at": str(r[2])} for r in rows]


def create_user(username: str, password: str, is_admin: bool = False) -> dict:
    conn = _get_conn()
    existing = conn.execute("SELECT username FROM auth_users WHERE username = ?", [username]).fetchone()
    if existing:
        raise ValueError(f"Usuario '{username}' ya existe")
    salt = _new_salt()
    pw_hash = _hash_password(password, salt)
    conn.execute(
        "INSERT INTO auth_users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, ?)",
        [username, pw_hash, salt, is_admin],
    )
    row = conn.execute("SELECT username, is_admin, created_at FROM auth_users WHERE username = ?", [username]).fetchone()
    return {"username": row[0], "is_admin": bool(row[1]), "created_at": str(row[2])}


def delete_user(username_to_delete: str, requesting_username: str) -> None:
    conn = _get_conn()
    row = conn.execute("SELECT username, is_admin FROM auth_users WHERE username = ?", [username_to_delete]).fetchone()
    if not row:
        raise ValueError("Usuario no encontrado")
    if row[0] == requesting_username:
        raise ValueError("No puedes eliminarte a ti mismo")
    if row[1]:
        admin_count = conn.execute("SELECT COUNT(*) FROM auth_users WHERE is_admin = TRUE").fetchone()[0]
        if admin_count <= 1:
            raise ValueError("No se puede eliminar el último administrador")
    conn.execute("DELETE FROM auth_users WHERE username = ?", [username_to_delete])


def reset_password(username: str, new_password: str) -> None:
    conn = _get_conn()
    row = conn.execute("SELECT username FROM auth_users WHERE username = ?", [username]).fetchone()
    if not row:
        raise ValueError("Usuario no encontrado")
    salt = _new_salt()
    pw_hash = _hash_password(new_password, salt)
    conn.execute(
        "UPDATE auth_users SET password_hash = ?, salt = ? WHERE username = ?",
        [pw_hash, salt, username],
    )


# ── Login page ────────────────────────────────────────────────────────────────

_LOGIN_HTML = """<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>SOC Dashboard — Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0 }
    body { background: #030712; color: #f9fafb; font-family: system-ui, sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px;
            padding: 2rem; width: 100%; max-width: 360px }
    h1 { font-size: 1.25rem; font-weight: 700; margin-bottom: 1.5rem }
    h1 span { color: #60a5fa }
    label { display: block; font-size: 0.75rem; color: #9ca3af; margin-bottom: 4px }
    input { width: 100%; background: #1f2937; border: 1px solid #374151; color: #fff;
            border-radius: 6px; padding: 8px 12px; font-size: 0.875rem; margin-bottom: 1rem }
    input:focus { outline: none; border-color: #3b82f6 }
    button { width: 100%; background: #2563eb; color: #fff; border: none; border-radius: 6px;
             padding: 10px; font-size: 0.875rem; font-weight: 600; cursor: pointer }
    button:hover { background: #1d4ed8 }
    .err { background: #450a0a; border: 1px solid #7f1d1d; color: #fca5a5;
           border-radius: 6px; padding: 8px 12px; font-size: 0.8rem; margin-bottom: 1rem }
  </style>
</head>
<body>
  <div class="card">
    <h1>SOC <span>Dashboard</span></h1>
    {error}
    <form method="post" action="/api/auth/login">
      <label>Usuario</label>
      <input name="username" type="text" autocomplete="username" required autofocus>
      <label>Contraseña</label>
      <input name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Ingresar</button>
    </form>
  </div>
</body>
</html>
"""


def login_page(error: bool = False) -> HTMLResponse:
    err_html = '<div class="err">Usuario o contraseña incorrectos</div>' if error else ""
    return HTMLResponse(_LOGIN_HTML.replace("{error}", err_html))


# ── FastAPI route handlers ────────────────────────────────────────────────────

async def handle_login(request: Request) -> RedirectResponse | HTMLResponse:
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))

    user = verify_credentials(username, password)
    if user:
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie(
            _COOKIE, _make_token(user["username"], user["is_admin"]),
            httponly=True, samesite="lax", max_age=_TTL,
        )
        return resp
    return login_page(error=True)


async def handle_logout(request: Request) -> RedirectResponse:
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(_COOKIE)
    return resp


# ── Middleware ────────────────────────────────────────────────────────────────

PUBLIC_PATHS = {"/login", "/api/auth/login", "/api/auth/logout"}


class AuthMiddleware:
    """Redirects unauthenticated requests to /login; returns 401 for API calls."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        if path in PUBLIC_PATHS or path.startswith("/assets/"):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_cookie = headers.get(b"cookie", b"").decode()
        token = None
        for part in raw_cookie.split(";"):
            part = part.strip()
            if part.startswith(f"{_COOKIE}="):
                token = part[len(f"{_COOKIE}="):]
                break

        user = _verify_token(token) if token else None

        if user:
            # Inject user info into request state via scope extensions
            scope.setdefault("app_user", user)
            await self.app(scope, receive, send)
            return

        if path.startswith("/api/"):
            response = JSONResponse({"detail": "Not authenticated"}, status_code=401)
        else:
            response = RedirectResponse(f"/login?next={path}", status_code=302)

        await response(scope, receive, send)
