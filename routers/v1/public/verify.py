from fastapi import APIRouter, Security, Request
from fastapi.responses import JSONResponse
from rfc9457 import UnauthorisedProblem

from core.logger import logger
from dependencies.security import get_current_user

verify_request_router = APIRouter()

@verify_request_router.api_route("/verify", methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
                                 operation_id="verify_auth_request")
async def verify_request(request: Request, payload: dict = Security(get_current_user)):
    try:
        original_method = request.headers.get("X-Forwarded-Method", "GET")
        original_host = request.headers.get("X-Forwarded-Host", "")
        original_uri = request.headers.get("X-Forwarded-Uri", "")

        logger.info(f"Verifying user token", extra={
            "user_id": payload.get('sub'),
            "email": payload.get('email'),
            "original_method": original_method,
            "original_host": original_host,
            "original_uri": original_uri
        })



        roles = ",".join(payload.get("roles", []))
        permissions = ",".join(payload.get("permissions", []))

        response_headers = {
            "X-User-ID": str(payload.get('sub')),
            "X-User-Email": payload.get("email", ""),
            "X-User-Role": roles,
            "X-Token-Expires": str(payload.get("exp", "")),
            "X-Permissions": permissions,
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


