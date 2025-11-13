from typing import Iterable

from fastapi import APIRouter, Security, Request
from fastapi.params import Depends
from fastapi.responses import JSONResponse
from rfc9457 import UnauthorisedProblem
from sqlalchemy.ext.asyncio import AsyncSession

from core.logger import logger
from database.crud.user import UserService
from database.db.session import get_async_db
from dependencies.security import get_current_user, JWTUser

verify_request_router = APIRouter()


def _clean_header_value(value: str | None) -> str:
    """Strip new lines and spaces to keep headers h11-compliant."""
    if not value:
        return ""
    return value.replace("\r", "").replace("\n", "").strip()


def _join_header_values(items: Iterable[str]) -> str:
    cleaned = []
    for item in items or []:
        if not isinstance(item, str):
            continue
        value = _clean_header_value(item)
        if value:
            cleaned.append(value)
    return ",".join(cleaned)


async def verify_request(request: Request, payload: JWTUser = Security(get_current_user),
                         db: AsyncSession = Depends(get_async_db)):
    try:
        original_method = request.headers.get("X-Forwarded-Method", "GET")
        original_host = request.headers.get("X-Forwarded-Host", "")
        original_uri = request.headers.get("X-Forwarded-Uri", "")

        logger.info("Verifying user token", extra={
            "user_id": payload.id,
            "email": payload.email,
            "original_method": original_method,
            "original_host": original_host,
            "original_uri": original_uri,
        })

        user_service = UserService(db)

        user = await user_service.get_user_by_uuid(str(payload.id))
        if not user:
            logger.warning("Authentication failed - user not found", extra={
                "user_uuid": payload.id,
                "jti": payload.token_jti,
            })
            raise UnauthorisedProblem("User not found")
        roles_permissions = await user_service.extract_roles_and_permissions_from_user(user_id=user.id, user=user)

        roles = _join_header_values(roles_permissions.get("roles", []))
        permissions = _join_header_values(roles_permissions.get("permissions", []))

        response_headers = {
            "X-User-ID": _clean_header_value(str(payload.id)),
            "X-User-Email": _clean_header_value(payload.email),
            "X-User-Role": roles,
            "X-Token-Expires": _clean_header_value(str(payload.token_expires)),
            "X-Permissions": permissions,
        }

        logger.info(f"Authentication successful for user: {payload.id}")

        return JSONResponse(
            status_code=200,
            content={"status": "authorized"},
            headers=response_headers,
        )

    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return UnauthorisedProblem(detail="Authentication failed")


for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
    verify_request_router.add_api_route(
        "/verify",
        verify_request,
        methods=[method],
        operation_id=f"verify_auth_request_{method.lower()}",
    )
