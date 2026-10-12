from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import ReferralWallet
from database.schemas.referral import ReferralWalletCreate, ReferralWalletUpdate


class ReferralWalletService(BaseService[ReferralWallet, ReferralWalletCreate, ReferralWalletUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(ReferralWallet, session)

    async def get_by_user_id(self, user_id: int, for_update: bool = False) -> Optional[ReferralWallet]:
        stmt = select(ReferralWallet).where(ReferralWallet.user_id == user_id)
        if for_update:
            stmt = stmt.with_for_update().execution_options(populate_existing=True)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
