from datetime import datetime
from typing import Optional

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import Referral
from database.schemas.referral import ReferralCreate, ReferralUpdate


class ReferralRecordService(BaseService[Referral, ReferralCreate, ReferralUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(Referral, session)

    async def get_by_referred_user_id(self, referred_user_id: int) -> Optional[Referral]:
        result = await self.session.execute(
            select(Referral).where(Referral.referred_user_id == referred_user_id)
        )
        return result.scalar_one_or_none()

    async def register_bid(self, referred_user_id: int, bid_at: datetime) -> None:
        await self.session.execute(
            update(Referral)
            .where(Referral.referred_user_id == referred_user_id)
            .values(
                bids_count=Referral.bids_count + 1,
                first_bid_at=func.coalesce(Referral.first_bid_at, bid_at),
            )
        )
        await self.session.commit()
