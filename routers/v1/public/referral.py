from fastapi import APIRouter, Body, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from core.logger import logger
from database.db.session import get_async_db
from deps import get_rate_limiter
from schemas.request_schemas.referral import ReferralVisitIn
from schemas.response_schemas.referral import ReferralVisitOut
from services.referral.referral_service import ReferralService
from utils.decode_user_agent import client_ip_from_request

referral_public_router = APIRouter()


@referral_public_router.post(
    "/visit",
    response_model=ReferralVisitOut,
    summary="Track referral link visit",
    description="Register a visit through a referral link. Repeated visits of the same visitor are counted once.",
    dependencies=[get_rate_limiter(times=30, seconds=60)],
)
async def track_referral_visit(
        request: Request,
        data: ReferralVisitIn = Body(...),
        db: AsyncSession = Depends(get_async_db),
) -> ReferralVisitOut:
    user_agent = request.headers.get("user-agent")
    visit = await ReferralService(db).track_visit(
        referral_code=data.referral_code,
        visitor_id=data.visitor_id,
        ip_address=client_ip_from_request(request),
        user_agent=user_agent[:1000] if user_agent else None,
        landing_url=data.landing_url,
    )
    if not visit:
        logger.info("Referral visit with unknown code", extra={"referral_code": data.referral_code})
        return ReferralVisitOut(valid=False)
    return ReferralVisitOut(valid=True, visit_id=visit.id)
