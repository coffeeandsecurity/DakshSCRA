import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Cookie, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from .config import ADMIN_PASSWORD, DEFAULT_ADMIN_PASSWORD, ADMIN_USERNAME, COOKIE_SECURE, SESSION_COOKIE_NAME, SESSION_TTL_HOURS
from .database import SessionLocal
from .models import User, UserSession


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_session(db: Session, user: User) -> str:
    """Create a new session for `user` and return the raw token to send
    the client as a cookie. Only the SHA-256 hash of the token is stored,
    so a leaked database row alone doesn't yield a valid session."""
    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    session_row = UserSession(
        token_hash=_hash_token(raw_token),
        user_id=user.id,
        expires_at=now + timedelta(hours=SESSION_TTL_HOURS),
        last_seen_at=now,
    )
    db.add(session_row)
    user.last_login_at = now
    db.commit()
    return raw_token


def delete_session(db: Session, raw_token: str) -> None:
    if not raw_token:
        return
    token_hash = _hash_token(raw_token)
    db.query(UserSession).filter(UserSession.token_hash == token_hash).delete()
    db.commit()


def get_session_user(db: Session, raw_token: str) -> Optional[User]:
    if not raw_token:
        return None
    token_hash = _hash_token(raw_token)
    session_row = db.query(UserSession).filter(UserSession.token_hash == token_hash).first()
    if not session_row:
        return None
    now = datetime.now(timezone.utc)
    expires_at = session_row.expires_at
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not expires_at or expires_at < now:
        db.delete(session_row)
        db.commit()
        return None
    session_row.last_seen_at = now
    db.commit()
    return db.query(User).filter(User.id == session_row.user_id).first()


def set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


def get_current_user(
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(_get_db),
) -> User:
    user = get_session_user(db, session_token or "")
    if not user:
        raise HTTPException(status_code=401, detail="not_authenticated")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="admin_required")
    return user


def require_password_ok(user: User = Depends(get_current_user)) -> User:
    """Blocks every route mounted behind it until a user with an
    admin-assigned password (initial bootstrap, admin-created account,
    admin password reset) has changed it. /auth/me, /auth/change-password,
    and /auth/logout are deliberately kept off this gate so the frontend
    can detect the flag and let the user actually change their password."""
    if user.must_change_password:
        raise HTTPException(status_code=403, detail="password_change_required")
    return user


def bootstrap_admin_user(db: Session) -> None:
    """Create the first admin account on startup if no users exist yet.

    Uses DAKSH_ADMIN_USERNAME/DAKSH_ADMIN_PASSWORD if set; otherwise the
    documented default password. Either way the account is flagged
    must_change_password, so the first login forces a new password.
    """
    if db.query(User).count() > 0:
        return

    password = ADMIN_PASSWORD
    using_default = password == DEFAULT_ADMIN_PASSWORD

    admin = User(
        username=ADMIN_USERNAME,
        password_hash=hash_password(password),
        is_admin=True,
        must_change_password=True,
    )
    db.add(admin)
    db.commit()

    print(f"\n  Created initial admin account: {ADMIN_USERNAME}")
    if using_default:
        print("  Initial password: the documented default. A password change is required at first login.\n")
    else:
        print("  Password set from DAKSH_ADMIN_PASSWORD. A password change is required at first login.\n")
