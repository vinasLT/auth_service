import email

from aioboto3 import Session
from aiobotocore.session import AioSession
from fastapi import Depends, HTTPException, status, APIRouter, Body, Request
from fastapi.security import HTTPAuthorizationCredentials
from fastapi_limiter.depends import RateLimiter
from redis import Redis
from rfc9457 import UnauthorisedProblem, ForbiddenProblem
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from datetime import datetime, UTC, timedelta
import uuid

from auth.service import AuthService
from config import settings
from custom_exceptions import EmailAlreadyRegistered
from database.crud.refresh_token import RefreshTokenService
from database.crud.role import RoleService
from database.crud.singin_key import SigningKeyService
from database.crud.user import UserService
from database.crud.user_role import UserRoleService
from database.crud.user_session import UserSessionService
from database.db.session import get_async_db
from database.models import User, Role, UserRole
from database.schemas.refresh_token import RefreshTokenCreate
from database.schemas.user import (
    UserCreate, UserLogin, TokenResponse, UserIn, UserRead, UserUpdate
)

from database.schemas.user_role import UserRoleCreate
from database.schemas.user_session import UserSessionCreate
from dependencies import get_kms_session, get_redis_client, get_auth_service
from rate_limit_ids import user_identifier
from request_schemas.refresh import RefreshTokenIn
from security import security_JWT, get_current_user
from utils import client_ip_from_request, device_name_from_user_agent

auth_v1_router = APIRouter()


@auth_v1_router.get("")
async def root():
    return {"message": "Hello World"}

@auth_v1_router.post(
    "/register",
    response_model=UserRead,
    summary="Register a new user",
    description="Create a new user account with email, username, and password.",
    dependencies=[Depends(RateLimiter(times=15, seconds=120, identifier=user_identifier))]
)
async def register(
    user_data: UserIn = Body(..., description="User registration payload"),
    db: AsyncSession = Depends(get_async_db),
    kms_session: Session = Depends(get_kms_session),
    redis: Redis = Depends(get_redis_client)
)-> User:
    user_service = UserService(db)
    result = await user_service.get_by_email(str(user_data.email))
    if result:
        raise EmailAlreadyRegistered(
            detail="Email already registered"
        )

    role_service = RoleService(db)
    user_role_service = UserRoleService(db)



    auth_service = AuthService(kms_session, redis, key_arn=str(active_singing_key.key_arn),
                               signing_algorithm=str(active_singing_key.alg))

    password_hash = auth_service.hash_password(user_data.password)

    default_role = await role_service.get_default_role()

    user_uuid = str(uuid.uuid4())
    user_data = UserCreate(uuid_key=user_uuid, password_hash=password_hash, email=user_data.email,
                           phone_number=user_data.phone_number, username=str(user_data.email).split('@')[0])
    user = await user_service.create(user_data, flush=True)

    user_role_data = UserRoleCreate(user_id=user.id, role_id=default_role.id)

    await user_role_service.create(user_role_data)

    await user_service.session.commit()

    return user


@auth_v1_router.post("/login", response_model=TokenResponse,
                     description="Login and receive tokens",
                     summary="Login",
                     dependencies=[Depends(RateLimiter(times=15, seconds=120, identifier=user_identifier))])
async def login(request: Request, credentials: UserLogin = Body(...), db: AsyncSession = Depends(get_async_db),
                redis_client: Redis = Depends(get_redis_client),
                kms_session: Session = Depends(get_kms_session)):

    user_service = UserService(db)
    sign_key_service = SigningKeyService(db)

    active_singing_key = await sign_key_service.get_newer_active_key()

    auth_service = AuthService(kms_session, redis_client, key_arn=str(active_singing_key.key_arn),
                               signing_algorithm=str(active_singing_key.alg))

    user = await user_service.get_user_with_permissions(str(credentials.email))

    if not user or not auth_service.verify_password(credentials.password, str(user.password_hash)):
        raise UnauthorisedProblem(
            detail="Invalid email or password"
        )

    if not user.is_active:
        raise ForbiddenProblem(
            detail="Account is deactivated"
        )

    user_agent = request.headers.get("user-agent", "")
    device_name = request.headers.get("x-device-name") or device_name_from_user_agent(user_agent)
    ip_address = client_ip_from_request(request)

    access_token_payload = await auth_service.get_payload_for_token(user_uuid=user.uuid_key, email=user.email, token_type="access")
    refresh_token_payload = await auth_service.get_payload_for_token(user_uuid=user.uuid_key, email=user.email, token_type="refresh")

    refresh_token_service = RefreshTokenService(db)
    refresh_token_data = RefreshTokenCreate(
        jti=refresh_token_payload["jti"],
        user_id=user.id,
        token_family=refresh_token_payload["token_family"],
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(seconds=auth_service.refresh_token_ttl),
        device_name=device_name,
        user_agent=user_agent,
        ip_address=ip_address,
        is_active=True,
    )

    refresh_token_created = await refresh_token_service.create(refresh_token_data)

    user_session_service = UserSessionService(db)
    user_session_data = UserSessionCreate(user_id=user.id, session_key=str(uuid.uuid4()), refresh_token_id=refresh_token_created.id)
    await user_session_service.create(user_session_data)

    access_token = await auth_service.generate_token(access_token_payload)
    refresh_token = await auth_service.generate_token(refresh_token_payload)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@auth_v1_router.post("/refresh", response_model=TokenResponse, description="Rotate refresh and issue new tokens", summary="Refresh")
async def refresh_token_pair(
    data: RefreshTokenIn = Body(...),
    db: AsyncSession = Depends(get_async_db),
    redis_client: Redis = Depends(get_redis_client),
    kms_session: Session = Depends(get_kms_session),
):
    sign_key_service = SigningKeyService(db)
    active_signing_key = await sign_key_service.get_newer_active_key()
    auth_service = AuthService(kms_session, redis_client, key_arn=str(active_signing_key.key_arn), signing_algorithm=str(active_signing_key.alg))

    payload = await auth_service.verify_token(data.refresh_token)
    presented_jti = str(payload.get("jti"))
    if not presented_jti or await auth_service.is_token_blacklisted('refresh', presented_jti):
        raise UnauthorisedProblem(detail="Refresh token expired or revoked, please login again")


    if not payload or payload.get("type") != "refresh":
        raise UnauthorisedProblem(detail="Invalid refresh token")

    user_service = UserService(db)
    user = await user_service.get_user_by_uuid(str(payload.get("sub")))
    if not user or not user.is_active:
        raise UnauthorisedProblem(detail="User not found or inactive")

    refresh_token_service = RefreshTokenService(db)
    family_id = str(payload.get("token_family"))


    last = await refresh_token_service.get_last_token_in_family(family_id, only_active=True, require_not_expired=True)
    if not last or last.jti != presented_jti:
        await refresh_token_service.revoke_family(family_id)
        await auth_service.blacklist_token('refresh', presented_jti)
        raise UnauthorisedProblem(detail="Refresh token reuse detected")

    now = datetime.now(UTC)
    new_refresh_payload = await auth_service.get_payload_for_token(user_uuid=user.uuid_key, email=user.email, token_type="refresh", token_family=family_id)
    new_access_payload = await auth_service.get_payload_for_token(user_uuid=user.uuid_key, email=user.email, token_type="access")

    new_expires_at = now + timedelta(seconds=auth_service.refresh_token_ttl)
    await refresh_token_service.rotate_refresh(current_jti=presented_jti, new_jti=str(new_refresh_payload["jti"]), new_expires_at=new_expires_at)

    access_token = await auth_service.generate_token(new_access_payload)
    refresh_token = await auth_service.generate_token(new_refresh_payload)

    await auth_service.blacklist_token('refresh', presented_jti)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@auth_v1_router.post("/auth/logout")
async def logout(
        token_data: dict = Depends(get_current_user),
        auth_service: AuthService = Depends(get_auth_service),
        db: AsyncSession = Depends(get_async_db),
):


   jti = token_data.get("jti")

   await auth_service.blacklist_token('access', jti)
   await auth_service.blacklist_token('refresh', jti)

   user_session_service = UserSessionService(db)
   refresh_token_service = RefreshTokenService(db)




   return {"message": "Successfully logged out"}




