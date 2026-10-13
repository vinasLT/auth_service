from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import ReferralReward
from database.schemas.referral import ReferralRewardCreate, ReferralRewardUpdate


class ReferralRewardService(BaseService[ReferralReward, ReferralRewardCreate, ReferralRewardUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(ReferralReward, session)

    async def get_by_external_purchase_id(self, external_purchase_id: str) -> Optional[ReferralReward]:
        result = await self.session.execute(
            select(ReferralReward).where(ReferralReward.external_purchase_id == external_purchase_id)
        )
        return result.scalar_one_or_none()
