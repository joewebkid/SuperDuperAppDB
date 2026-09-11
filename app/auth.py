"""GitHub OAuth login + session-backed authentication helpers."""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time

# Optional import: deployments can drop a small ``_runtime_env.py`` next to
# this module to populate ``os.environ`` with secrets that aren't checked
# into git (OAuth client id/secret, session secret). The file is excluded
# from the repository via ``.gitignore`` and is created by the deploy
# pipeline, never by the application itself.
try:
    from . import _runtime_env  # noqa: F401  (side effects only)
except ImportError:
    pass
from typing import Annotated
from urllib.parse import unquote, urlencode, urlsplit

import httpx
from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from .db import User, admin_github_logins, get_db, utcnow


GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

OAUTH_STATE_COOKIE = "hyperhle_oauth_state"
SESSION_USER_KEY = "user_id"
OAUTH_STATE_KEY = "oauth_state"
OAUTH_STARTED_AT_KEY = "oauth_started_at"
OAUTH_PKCE_VERIFIER_KEY = "oauth_pkce_verifier"
OAUTH_NEXT_KEY = "oauth_next"
CSRF_SESSION_KEY = "csrf_token"
OAUTH_MAX_AGE_SECONDS = 10 * 60


class OAuthConfig:
    """Read OAuth config from env vars on each access so tests / runtime
    overrides are picked up without restarting the import."""

    @property
    def client_id(self) -> str | None:
        return os.environ.get("GITHUB_OAUTH_CLIENT_ID")

    @property
    def client_secret(self) -> str | None:
        return os.environ.get("GITHUB_OAUTH_CLIENT_SECRET")

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)


oauth_config = OAuthConfig()


def _is_admin_login(login: str | None) -> bool:
    return bool(login) and login.lower() in admin_github_logins()


def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User | None:
    """Return the logged-in :class:`User` or ``None`` for anonymous requests."""
    user_id = request.session.get(SESSION_USER_KEY)
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


CurrentUserDep = Annotated[User | None, Depends(get_current_user)]


def require_login(user: CurrentUserDep) -> User:
    if user is None:
        raise HTTPException(status_code=401, detail="login_required")
    return user


def require_admin(user: CurrentUserDep) -> User:
    if user is None:
        raise HTTPException(status_code=401, detail="login_required")
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="admin_required")
    return user


RequireLoginDep = Annotated[User, Depends(require_login)]
RequireAdminDep = Annotated[User, Depends(require_admin)]


def _absolute_callback_url(request: Request) -> str:
    """Build the OAuth callback URL based on the incoming request.

    Honours ``X-Forwarded-Proto`` / ``-Host`` (we install
    :class:`ProxyHeadersMiddleware` so ``request.url`` is correct).
    Optionally overridable via ``OAUTH_CALLBACK_URL``.
    """
    override = os.environ.get("OAUTH_CALLBACK_URL")
    if override:
        return override
    return str(request.url_for("github_callback"))


def safe_next_path(value: str | None) -> str | None:
    """Return a local redirect target, rejecting protocol-relative variants."""
    if not value or len(value) > 2048 or not value.startswith("/"):
        return None
    decoded = unquote(value)
    if decoded.startswith("//") or "\\" in decoded:
        return None
    if any(ord(character) < 0x20 for character in value):
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return None
    return value


def get_csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def require_csrf_token(request: Request, supplied: str | None) -> None:
    expected = request.session.get(CSRF_SESSION_KEY)
    if (
        not isinstance(expected, str)
        or not isinstance(supplied, str)
        or not secrets.compare_digest(expected, supplied)
    ):
        raise HTTPException(status_code=403, detail="Invalid or expired form token.")


def _clear_oauth_attempt(request: Request) -> None:
    request.session.pop(OAUTH_STATE_KEY, None)
    request.session.pop(OAUTH_STARTED_AT_KEY, None)
    request.session.pop(OAUTH_PKCE_VERIFIER_KEY, None)


def _consume_oauth_attempt(request: Request, state: str | None) -> str:
    expected_state = request.session.get(OAUTH_STATE_KEY)
    started_at = request.session.get(OAUTH_STARTED_AT_KEY)
    verifier = request.session.get(OAUTH_PKCE_VERIFIER_KEY)
    _clear_oauth_attempt(request)
    if (
        not isinstance(expected_state, str)
        or not isinstance(state, str)
        or not secrets.compare_digest(expected_state, state)
    ):
        request.session.pop(OAUTH_NEXT_KEY, None)
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")
    if (
        not isinstance(started_at, (int, float))
        or time.time() - float(started_at) > OAUTH_MAX_AGE_SECONDS
        or time.time() < float(started_at) - 30
    ):
        request.session.pop(OAUTH_NEXT_KEY, None)
        raise HTTPException(status_code=400, detail="OAuth attempt expired. Please sign in again.")
    if not isinstance(verifier, str):
        request.session.pop(OAUTH_NEXT_KEY, None)
        raise HTTPException(status_code=400, detail="OAuth verifier is missing.")
    return verifier


def start_login(request: Request, next_path: str | None = None) -> RedirectResponse:
    if not oauth_config.configured:
        raise HTTPException(
            status_code=503,
            detail=(
                "GitHub login is not configured on this server. "
                "Set GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET."
            ),
        )

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    request.session[OAUTH_STATE_KEY] = state
    request.session[OAUTH_STARTED_AT_KEY] = time.time()
    request.session[OAUTH_PKCE_VERIFIER_KEY] = verifier
    request.session.pop(OAUTH_NEXT_KEY, None)
    safe_next = safe_next_path(next_path)
    if safe_next:
        request.session[OAUTH_NEXT_KEY] = safe_next

    qs = urlencode(
        {
            "client_id": oauth_config.client_id,
            "redirect_uri": _absolute_callback_url(request),
            "scope": "read:user",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "allow_signup": "true",
        }
    )
    return RedirectResponse(f"{GITHUB_AUTHORIZE_URL}?{qs}", status_code=303)


async def handle_callback(
    request: Request, code: str, state: str, db: Session,
) -> RedirectResponse:
    verifier = _consume_oauth_attempt(request, state)
    if not oauth_config.configured:
        raise HTTPException(status_code=503, detail="OAuth is not configured.")

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_resp = await client.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id": oauth_config.client_id,
                    "client_secret": oauth_config.client_secret,
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": _absolute_callback_url(request),
                },
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"GitHub token endpoint returned {token_resp.status_code}.",
                )
            try:
                token_data = token_resp.json()
            except ValueError as error:
                raise HTTPException(
                    status_code=502, detail="GitHub token endpoint returned invalid JSON."
                ) from error
            access_token = token_data.get("access_token")
            if not isinstance(access_token, str) or not access_token:
                # Never include the response body: it can contain credentials.
                raise HTTPException(
                    status_code=502, detail="GitHub did not return an access token."
                )

            user_resp = await client.get(
                GITHUB_USER_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if user_resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"GitHub /user returned {user_resp.status_code}.",
                )
            try:
                gh_user = user_resp.json()
            except ValueError as error:
                raise HTTPException(
                    status_code=502, detail="GitHub /user returned invalid JSON."
                ) from error
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail="Could not reach GitHub OAuth.") from error

    gh_id = gh_user.get("id")
    gh_login = gh_user.get("login")
    if not gh_id or not gh_login:
        raise HTTPException(status_code=502, detail="GitHub /user response missing id/login.")

    user = db.query(User).filter(User.github_id == gh_id).first()
    is_admin = _is_admin_login(gh_login)
    now = utcnow()
    if user is None:
        user = User(
            github_id=gh_id,
            github_login=gh_login,
            avatar_url=gh_user.get("avatar_url"),
            is_admin=is_admin,
            created_at=now,
            last_login_at=now,
        )
        db.add(user)
    else:
        user.github_login = gh_login
        user.avatar_url = gh_user.get("avatar_url")
        user.is_admin = is_admin
        user.last_login_at = now
    db.commit()
    db.refresh(user)

    request.session[SESSION_USER_KEY] = user.id

    next_path = safe_next_path(request.session.pop(OAUTH_NEXT_KEY, None)) or "/"
    return RedirectResponse(next_path, status_code=303)


def handle_authorization_error(request: Request, state: str | None) -> None:
    """Consume a failed OAuth attempt without reflecting provider text."""
    _consume_oauth_attempt(request, state)
    request.session.pop(OAUTH_NEXT_KEY, None)
    raise HTTPException(status_code=400, detail="GitHub authorization was cancelled or denied.")


def logout(request: Request) -> RedirectResponse:
    request.session.pop(SESSION_USER_KEY, None)
    _clear_oauth_attempt(request)
    request.session.pop(OAUTH_NEXT_KEY, None)
    request.session.pop(CSRF_SESSION_KEY, None)
    return RedirectResponse("/", status_code=303)


__all__ = [
    "CurrentUserDep",
    "RequireAdminDep",
    "RequireLoginDep",
    "get_current_user",
    "get_csrf_token",
    "handle_callback",
    "handle_authorization_error",
    "logout",
    "oauth_config",
    "require_admin",
    "require_csrf_token",
    "require_login",
    "start_login",
    "safe_next_path",
]
