"""에이전트 토큰 인증과 브라우저 로그인(별도)."""
import base64
import hashlib
import hmac
import secrets
import time
from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException, Request

from . import config, db

COOKIE = "ps_session"


# ---------------------------------------------------------------- agent token

def token_sha256(token: str) -> str:
    return hashlib.sha256(token.strip().encode()).hexdigest()


def require_agent(request: Request) -> str:
    """Authorization: Bearer <token>. 토큰 해시로 조회, 폐기된 토큰 거부."""
    h = request.headers.get("authorization", "")
    if not h.lower().startswith("bearer ") or len(h) < 20:
        raise HTTPException(401, "missing bearer token")
    th = token_sha256(h[7:])
    with db.connect() as conn:
        row = conn.execute(
            "UPDATE agents SET last_seen = now() WHERE token_sha256 = %s AND revoked_at IS NULL RETURNING agent_id",
            (th,),
        ).fetchone()
    if not row:
        raise HTTPException(401, "invalid or revoked token")
    hdr = request.headers.get("x-patchscope-agent")
    if hdr and hdr != row["agent_id"]:
        raise HTTPException(403, "agent id mismatch")
    return row["agent_id"]


# ---------------------------------------------------------------- admin login

def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, salt, want = stored.strip().split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(got.hex(), want)


@lru_cache(maxsize=1)
def _session_key() -> bytes:
    return Path(config.SESSION_KEY_FILE).read_bytes().strip()


def admin_hash() -> str:
    return Path(config.ADMIN_HASH_FILE).read_text().strip()


def _sign(payload: str) -> str:
    return hmac.new(_session_key(), payload.encode(), hashlib.sha256).hexdigest()


def make_cookie(user: str) -> str:
    payload = f"{user}|{int(time.time()) + config.SESSION_TTL_SECONDS}"
    return base64.urlsafe_b64encode(payload.encode()).decode() + "." + _sign(payload)


def cookie_user(request: Request) -> str | None:
    v = request.cookies.get(COOKIE)
    if not v or "." not in v:
        return None
    b, sig = v.rsplit(".", 1)
    try:
        payload = base64.urlsafe_b64decode(b.encode()).decode()
        user, exp = payload.split("|")
    except Exception:
        return None
    if not hmac.compare_digest(_sign(payload), sig) or int(exp) < time.time():
        return None
    return user


class LoginRequired(Exception):
    pass


def require_user(request: Request) -> str:
    u = cookie_user(request)
    if not u:
        raise LoginRequired()
    return u
