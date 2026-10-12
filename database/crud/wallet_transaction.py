from sqlalchemy import select, Select
from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import WalletTransaction, ReferralWallet
from database.schemas.referral import WalletTransactionCreate, WalletTransactionUpdate


class WalletTransactionService(BaseService[WalletTransaction, WalletTransactionCreate, WalletTransactionUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(WalletTransaction, session)

    def get_user_transactions_stmt(self, user_id: int) -> Select[tuple[WalletTransaction]]:
        return (
            select(WalletTransaction)
            .join(ReferralWallet, ReferralWallet.id == WalletTransaction.wallet_id)
            .where(ReferralWallet.user_id == user_id)
            .order_by(WalletTransaction.created_at.desc(), WalletTransaction.id.desc())
        )
