"""Authentication routes: registration, login, and GitHub OAuth."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from supplyguard.api.deps import CurrentUser, SessionDep
from supplyguard.api.schemas import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from supplyguard.api.security import create_access_token, hash_password, verify_password
from supplyguard.config import get_settings
from supplyguard.db.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, session: SessionDep) -> TokenResponse:
    existing = await session.scalar(select(User).where(User.email == payload.email.lower()))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="That email is already registered."
        )
    try:
        hashed = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    user = User(
        email=payload.email.lower(),
        hashed_password=hashed,
        display_name=payload.display_name,
    )
    session.add(user)
    await session.flush()
    settings = get_settings()
    return TokenResponse(
        access_token=create_access_token(user.id),
        expires_in_minutes=settings.jwt_expiry_minutes,
    )


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, session: SessionDep) -> TokenResponse:
    user = await session.scalar(select(User).where(User.email == payload.email.lower()))
    # Verify against a dummy hash when the user does not exist, so that a
    # missing account and a wrong password take the same time to answer.
    hashed = user.hashed_password if user and user.hashed_password else _DUMMY_HASH
    valid = verify_password(payload.password, hashed)
    if user is None or not valid or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password."
        )
    settings = get_settings()
    return TokenResponse(
        access_token=create_access_token(user.id),
        expires_in_minutes=settings.jwt_expiry_minutes,
    )


@router.get("/me", response_model=UserResponse)
async def me(user: CurrentUser) -> User:
    return user


@router.get("/github/authorize")
async def github_authorize() -> dict:
    """Return the GitHub OAuth URL to redirect the browser to."""
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and "
            "GITHUB_CLIENT_SECRET.",
        )
    state = secrets.token_urlsafe(24)
    return {
        "authorize_url": (
            "https://github.com/login/oauth/authorize"
            f"?client_id={settings.github_client_id}"
            "&scope=read:user%20repo"
            f"&state={state}"
        ),
        "state": state,
    }


@router.post("/github/callback", response_model=TokenResponse)
async def github_callback(code: str, session: SessionDep) -> TokenResponse:
    """Exchange an OAuth code for a SupplyGuard token.

    The GitHub access token is stored on the user so that CI monitoring can
    read workflow runs from private repositories on their behalf.
    """
    settings = get_settings()
    if not (settings.github_client_id and settings.github_client_secret):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="GitHub OAuth is not configured."
        )

    import httpx

    async with httpx.AsyncClient(timeout=15.0) as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
            },
        )
        token_payload = token_response.json()
        access_token = token_payload.get("access_token")
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"GitHub rejected the authorization code: "
                f"{token_payload.get('error_description', 'unknown error')}",
            )
        profile_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        profile = profile_response.json()

    login_name = profile.get("login")
    email = profile.get("email") or f"{login_name}@users.noreply.github.com"
    user = await session.scalar(select(User).where(User.github_login == login_name))
    if user is None:
        user = await session.scalar(select(User).where(User.email == email.lower()))
    if user is None:
        user = User(email=email.lower(), display_name=profile.get("name") or login_name)
        session.add(user)
    user.github_login = login_name
    user.github_access_token = access_token
    await session.flush()

    return TokenResponse(
        access_token=create_access_token(user.id),
        expires_in_minutes=settings.jwt_expiry_minutes,
    )


#: A real bcrypt hash of a random value, used to equalise login timing.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
