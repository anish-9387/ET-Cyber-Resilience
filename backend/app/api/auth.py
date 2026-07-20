from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from pydantic import BaseModel, Field
from typing import Optional
from app.core.database import get_db
from app.core.security import verify_password, get_password_hash, create_access_token, decode_access_token
from app.models import User
from app.core.logger import logger

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    roles: list[str] = Field(
        default_factory=list,
        description=(
            "Requested roles. Privileged roles (approver, soc_lead, ciso, admin) "
            "are only granted to the bootstrap account; otherwise they are "
            "dropped and the account defaults to 'analyst'."
        ),
    )


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    roles: list[str] = []
    is_active: bool

    class Config:
        from_attributes = True


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(request.password, user.hashed_password):
        logger.warning("Failed login attempt", username=request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )
    from app.core.config import settings
    access_token = create_access_token(
        data={"sub": user.id, "username": user.username, "roles": user.roles},
    )
    logger.info("User logged in", username=user.username, user_id=user.id)
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(request: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(
        (User.username == request.username) | (User.email == request.email)
    ))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )
    # `roles` used to be accepted and silently dropped, so every account was
    # created with no roles and nobody could ever satisfy the approval gate.
    # Roles are now persisted, but privileged ones cannot be self-assigned
    # through open registration - otherwise anyone could mint themselves an
    # approver and walk straight through the human-in-the-loop control.
    requested = {str(r).lower() for r in (request.roles or [])}
    privileged = {"approver", "soc_lead", "ciso", "admin"}

    total_users = await db.execute(select(func.count(User.id)))
    is_first_account = (total_users.scalar() or 0) == 0

    if is_first_account:
        granted = sorted(requested) or ["admin"]
        logger.warning(
            "bootstrap_account_created",
            username=request.username,
            roles=granted,
            note="first account may self-assign roles; disable open registration in production",
        )
    else:
        denied = requested & privileged
        granted = sorted(requested - privileged) or ["analyst"]
        if denied:
            logger.warning(
                "privileged_role_self_assignment_denied",
                username=request.username,
                denied=sorted(denied),
            )

    user = User(
        username=request.username,
        email=request.email,
        hashed_password=get_password_hash(request.password),
        full_name=request.full_name,
        roles=granted,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("User registered", username=user.username, user_id=user.id)
    return user


@router.post("/verify")
async def verify_token(token: str):
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return {"valid": True, "sub": payload.get("sub"), "username": payload.get("username")}


@router.post("/change-password")
async def change_password(
    request: PasswordChange,
    token: str,
    db: AsyncSession = Depends(get_db),
):
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not verify_password(request.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    user.hashed_password = get_password_hash(request.new_password)
    await db.commit()
    logger.info("Password changed", user_id=user_id)
    return {"message": "Password updated successfully"}
