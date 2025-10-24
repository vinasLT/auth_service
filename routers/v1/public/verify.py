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

@verify_request_router.api_route("/verify", methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
                                 operation_id="verify_auth_request")
async def verify_request(request: Request, payload: JWTUser = Security(get_current_user),
                         db: AsyncSession = Depends(get_async_db)):
    try:
        original_method = request.headers.get("X-Forwarded-Method", "GET")
        original_host = request.headers.get("X-Forwarded-Host", "")
        original_uri = request.headers.get("X-Forwarded-Uri", "")

        logger.info(f"Verifying user token", extra={
            "user_id": payload.id,
            "email": payload.email,
            "original_method": original_method,
            "original_host": original_host,
            "original_uri": original_uri
        })

        user_service = UserService(db)

        print(payload.id)

        user = await user_service.get_user_by_uuid(str(payload.id))
        if not user:
            logger.warning(f'Authentication failed - user not found', extra={'user_uuid': payload.id,
                                                                             'jti': payload.token_jti})
            raise UnauthorisedProblem("User not found")
        roles_permissions = await user_service.extract_roles_and_permissions_from_user(user_id=user.id, user=user)


        roles = ",".join(roles_permissions.get("roles", []))
        permissions = ",".join(roles_permissions.get("permissions", []))

        response_headers = {
            "X-User-ID": str(payload.get('sub')),
            "X-User-Email": payload.get("email", ""),
            "X-User-Role": roles,
            "X-Token-Expires": str(payload.get("exp", "")),
            "X-Permissions": permissions
        }

        logger.info(f"Authentication successful for user: {payload.get('sub')}")

        return JSONResponse(
            status_code=200,
            content={"status": "authorized"},
            headers=response_headers
        )

    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return UnauthorisedProblem(
            detail="Authentication failed"
        )


