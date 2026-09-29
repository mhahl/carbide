"""Console auth: DB-backed users, pbkdf2 passwords, cookie sessions."""
import base64
import datetime
import functools
import hashlib
import hmac
import secrets

from aiohttp import web

COOKIE = "carbide_sess"
ITERATIONS = 600_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt, ITERATIONS)
    return (f"pbkdf2-sha256${ITERATIONS}"
            f"${base64.b64encode(salt).decode()}"
            f"${base64.b64encode(dk).decode()}")


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b, hash_b = (stored or "").split("$", 3)
        if algo != "pbkdf2-sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            base64.b64decode(salt_b), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(hash_b))
    except Exception:
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_sha(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


async def current_user(request: web.Request):
    token = request.cookies.get(COOKIE, "")
    if not token:
        return None
    row = await request.app["db"].get_web_session(token_sha(token))
    if not row:
        return None
    _sha, user_id, expires_at, username, disabled = row
    if disabled:
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    if expires_at < _utcnow():
        await request.app["db"].delete_web_session(token_sha(token))
        return None
    return {"id": user_id, "username": username}


def require_auth(handler):
    @functools.wraps(handler)
    async def wrapper(request: web.Request):
        user = await current_user(request)
        if user is None:
            if request.headers.get("HX-Request"):
                return web.Response(status=401, text="login required",
                                    headers={"HX-Redirect": "/login"})
            raise web.HTTPFound(f"/login?next={request.path}")
        request["user"] = user
        return await handler(request)
    return wrapper
