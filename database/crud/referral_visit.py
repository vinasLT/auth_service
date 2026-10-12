from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import ReferralVisit
from database.schemas.referral import ReferralVisitCreate, ReferralVisitUpdate


class ReferralVisitService(BaseService[ReferralVisit, ReferralVisitCreate, ReferralVisitUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(ReferralVisit, session)

    async def get_by_referrer_and_visitor(self, referrer_id: int, visitor_id: str) -> Optional[ReferralVisit]:
        result = await self.session.execute(
            select(ReferralVisit).where(
                ReferralVisit.referrer_id == referrer_id,
                ReferralVisit.visitor_id == visitor_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_recent_by_fingerprint(
            self,
            referrer_id: int,
            ip_address: str,
            user_agent: Optional[str],
            since: datetime,
    ) -> Optional[ReferralVisit]:
        stmt = select(ReferralVisit).where(
            ReferralVisit.referrer_id == referrer_id,
            ReferralVisit.visitor_id.is_(None),
            ReferralVisit.ip_address == ip_address,
            ReferralVisit.created_at >= since,
        )
        if user_agent is None:
            stmt = stmt.where(ReferralVisit.user_agent.is_(None))
        else:
            stmt = stmt.where(ReferralVisit.user_agent == user_agent)
        result = await self.session.execute(stmt.order_by(ReferralVisit.created_at.desc()).limit(1))
        return result.scalar_one_or_none()
