from typing import Dict, Optional

from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from rfc9457 import UnauthorisedProblem

from auth.service import AuthService

from dependencies import get_auth_service

security_JWT = HTTPBearer()


async def get_current_user(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_JWT),
        auth_service: AuthService = Depends(get_auth_service),
) -> Optional[Dict]:
    if not credentials:
        return None

    token = credentials.credentials

    payload = await auth_service.verify_token(token)
    if not payload:
        raise UnauthorisedProblem(detail="Invalid token")

    is_blacklisted = auth_service.is_token_blacklisted('access', str(payload.get("jti")))
    if is_blacklisted:
        raise UnauthorisedProblem(detail="Token revoked")

    return payload