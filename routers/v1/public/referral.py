import re
import uuid

from fastapi import APIRouter, Body, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings, Environment
from core.logger import logger
from database.db.session import get_async_db
from deps import get_rate_limiter
from schemas.request_schemas.referral import ReferralVisitIn
from schemas.response_schemas.referral import ReferralVisitOut
from services.referral.referral_service import ReferralService

referral_public_router = APIRouter()

VISITOR_COOKIE = "referral_visitor_id"
VISITOR_COOKIE_MAX_AGE = 60 * 60 * 24 * 365
_VISITOR_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _visitor_id_from_cookie(request: Request) -> str | None:
    raw = request.cookies.get(VISITOR_COOKIE)
    if raw and _VISITOR_ID_RE.fullmatch(raw):
        return raw
    return None


def _set_visitor_cookie(response: Response, visitor_id: str) -> None:
    response.set_cookie(
        key=VISITOR_COOKIE,
        value=visitor_id,
        max_age=VISITOR_COOKIE_MAX_AGE,
        httponly=True,
        secure=settings.ENVIRONMENT == Environment.PRODUCTION,
        samesite="lax",
    )


@referral_public_router.post(
    "/visit",
    response_model=ReferralVisitOut,
    summary="Track referral link visit",
    description="Register a visit through a referral link. The visitor id is created here and returned "
                "in the referral_visitor_id cookie. Repeated visits with that cookie are counted once.",
    dependencies=[get_rate_limiter(times=30, seconds=60)],
)
async def track_referral_visit(
        request: Request,
        response: Response,
        data: ReferralVisitIn = Body(...),
        db: AsyncSession = Depends(get_async_db),
) -> ReferralVisitOut:
    visitor_id = _visitor_id_from_cookie(request) or str(uuid.uuid4())
    visit = await ReferralService(db).track_visit(
        referral_code=data.referral_code,
        visitor_id=visitor_id,
    )
    _set_visitor_cookie(response, visitor_id)
    if not visit:
        logger.info("Referral visit with unknown code", extra={"referral_code": data.referral_code})
        return ReferralVisitOut(valid=False)
    return ReferralVisitOut(valid=True, visit_id=visit.id)
