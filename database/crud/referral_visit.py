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
