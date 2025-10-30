from datetime import datetime
from typing import Dict, Optional, Any

import jwt
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import Field, BaseModel, field_validator, ValidationError
from rfc9457 import UnauthorisedProblem
from sqlalchemy.ext.asyncio import AsyncSession

from auth.service import AuthService, TokenType
from config import Permissions
from core.logger import logger
from custom_exceptions import NotEnoughPermissionsProblem
from database.crud.user import UserService
from database.db.session import get_async_db

from deps import get_auth_service

security_JWT = HTTPBearer(auto_error=False)

class JWTUser(BaseModel):
    id: str = Field(..., description="User UUID")
    email: str = Field("", description="Email")
    first_name: str = Field(..., description='User first name')
    last_name: str = Field(..., description='User last name')
    role: list[str] = Field(default_factory=list, description="Roles")
    permissions: list[str] = Field(default_factory=list, description="Permissions")
    token_expires: Optional[datetime] = Field(None, description="Token expiration date")
    token_jti: str = Field(..., description="JWT access token JTI")

    model_config = {
        "validate_assignment": True,
    }

    @classmethod
    def parse_lists(cls, v):
        if isinstance(v, str):
            return [p.strip() for p in v.split(',') if p.strip()]
        return v or []

    @field_validator('permissions', mode='before')
    @classmethod
    def parse_permissions(cls, v: Any) -> list[str]:
        return cls.parse_lists(v)

    @field_validator('role', mode='before')
    @classmethod
    def parse_role(cls, v: Any) -> list[str]:
        return cls.parse_lists(v)

    @field_validator('token_expires', mode='before')
    @classmethod
    def parse_expires(cls, v: Any) -> Optional[datetime]:
        if isinstance(v, str) and v.isdigit():
            try:
                return datetime.fromtimestamp(int(v))
            except (ValueError, OSError):
                logger.exception("Invalid token expiration date")
                return None
        return v

    @property
    def is_token_expired(self) -> bool:
        if not self.token_expires:
            return False
        return datetime.now() > self.token_expires

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def has_any_permission(self, *permissions: str) -> bool:
        return any(perm in self.permissions for perm in permissions)

    def has_all_permissions(self, *permissions: str) -> bool:
        return all(perm in self.permissions for perm in permissions)

    def has_role(self, role: str) -> bool:
        return role.lower() in [r.lower() for r in self.role]

    def has_any_role(self, *roles: str) -> bool:
        user_roles = [r.lower() for r in self.role]
        return any(role.lower() in user_roles for role in roles)

    def has_all_roles(self, *roles: str) -> bool:
        user_roles = [r.lower() for r in self.role]
        return all(role.lower() in user_roles for role in roles)


async def get_current_user(
        credentials: HTTPAuthorizationCredentials | None = Depends(security_JWT),
        auth_service: AuthService = Depends(get_auth_service),
        db: AsyncSession = Depends(get_async_db)
) -> JWTUser:
    logger.debug("get_current_user called")
    if not credentials:
        logger.warning("Authorization credentials missing")
        raise UnauthorisedProblem(detail="Authorization header required")

    logger.debug(
        "Authorization credentials received",
        extra={
            "auth_scheme": credentials.scheme,
        }
    )

    token = credentials.credentials
    try:
        payload = await auth_service.verify_token(token)
    except Exception as exc:
        logger.exception(
            "Token verification failed",
            extra={
                "error": str(exc),
            }
        )
        raise

    if not payload:
        logger.warning("Invalid token")
        raise UnauthorisedProblem(detail="Invalid token")

    logger.debug(
        "Token verified successfully",
        extra={
            "user_uuid": payload.get("sub"),
            "jti": payload.get("jti"),
            "expires": payload.get("exp"),
        }
    )

    is_blacklisted = await auth_service.is_token_blacklisted(TokenType.ACCESS, str(payload.get("jti")))
    if is_blacklisted:
        logger.warning("Token revoked")
        raise UnauthorisedProblem(detail="Token revoked")

    logger.debug(
        "Token not blacklisted",
        extra={
            "user_uuid": payload.get("sub"),
            "jti": payload.get("jti"),
        }
    )

    user_service = UserService(db)
    logger.debug(
        "Fetching user from database",
        extra={
            "user_uuid": payload.get("sub"),
        }
    )
    user = await user_service.get_user_by_uuid(str(payload.get("sub")))
    if not user:
        logger.warning(f'Authentication failed - user not found', extra={'user_uuid': payload.get("sub"),
                                                                             'jti': payload.get("jti")})
        raise UnauthorisedProblem("User not found")
    roles_permissions = await user_service.extract_roles_and_permissions_from_user(user_id=user.id, user=user)
    logger.debug(
        "Extracted roles and permissions for user",
        extra={
            "user_uuid": payload.get("sub"),
            "roles_count": len(roles_permissions.get("roles", [])),
            "permissions_count": len(roles_permissions.get("permissions", [])),
        }
    )

    user = extract_user_from_payload(payload)
    user.role = roles_permissions.get("roles", [])
    user.permissions = roles_permissions.get("permissions", [])
    logger.info(
        "Successfully retrieved current user",
        extra={
            "user_uuid": user.id,
            "roles": user.role,
            "permissions": user.permissions,
        }
    )
    return user


def decode_jwt_without_signature(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False}
        )
        return payload
    except Exception as e:
        logger.warning(f"Error decoding JWT token", extra={
            'error': str(e),
        })
        raise UnauthorisedProblem(detail=f"Invalid JWT token: {str(e)}")

def extract_user_from_payload(payload: Dict[str, Any]) -> JWTUser:
    user_uuid = payload.get("sub")
    first_name = payload.get("first_name")
    last_name = payload.get("last_name")
    email = payload.get("email")
    token_expires = payload.get("exp")
    jti = payload.get("jti")

    try:
        user = JWTUser(
            id=user_uuid,
            first_name=first_name,
            last_name=last_name,
            email=email,
            token_expires=token_expires,
            token_jti=jti
        )
    except ValidationError as e:
        logger.warning(f"Error decoding JWT token", extra={
            'error': str(e),
        })
        raise UnauthorisedProblem(detail=f"Invalid JWT token: {str(e)}")
    return user


class RequirePermission:
    def __init__(
            self,
            permissions: list[Permissions] = None,
            require_all: bool = False,
            require_token: bool = True
    ):
        self.permissions = permissions or []
        self.require_all = require_all
        self.require_token = require_token

    def __call__(self, user: JWTUser = Depends(get_current_user)) -> JWTUser:
        if not self.require_token:
            return user

        if self.permissions:
            permission_strings = [perm.value if hasattr(perm, 'value') else str(perm)
                                  for perm in self.permissions]

            if self.require_all:
                if not user.has_all_permissions(*permission_strings):
                    logger.warning(
                        'User doesnt have all required permissions',
                        extra={
                            'required_permissions': permission_strings,
                            'user_permissions': user.permissions
                        }
                    )
                    raise NotEnoughPermissionsProblem(detail="Missing permissions")
            else:
                if not user.has_any_permission(*permission_strings):
                    logger.warning(
                        'User doesnt have any required permissions',
                        extra={
                            'required_permissions': permission_strings,
                            'user_permissions': user.permissions
                        }
                    )
                    raise NotEnoughPermissionsProblem(detail="Missing permissions")

        return user


def require_permission(
        permissions: list[Permissions],
        require_all: bool = False
) -> RequirePermission:
    return RequirePermission(permissions, require_all)


def require_any_permission(*permissions: Permissions) -> RequirePermission:
    return RequirePermission(list(permissions), require_all=False)


def require_all_permissions(*permissions: Permissions) -> RequirePermission:
    return RequirePermission(list(permissions), require_all=True)
