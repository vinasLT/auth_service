from datetime import datetime, UTC
from typing import Optional

from rfc9457 import NotFoundProblem
from sqlalchemy.ext.asyncio import AsyncSession

from core.logger import logger
from custom_exceptions import InsufficientWalletBalanceProblem
from database.crud.referral_reward import ReferralRewardService
from database.crud.referral_wallet import ReferralWalletService
from database.models import ReferralWallet, WalletTransaction, ReferralReward
from database.models.referral_reward import RewardStatus
from database.models.wallet_transaction import WalletTransactionType


class WalletService:
    """Every balance change locks the wallet row and writes a ledger entry in the same transaction."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.wallet_service = ReferralWalletService(session)
        self.reward_service = ReferralRewardService(session)

    async def get_or_create_wallet(self, user_id: int, lock: bool = False) -> ReferralWallet:
        wallet = await self.wallet_service.get_by_user_id(user_id, for_update=lock)
        if wallet:
            return wallet
        wallet = ReferralWallet(user_id=user_id, balance_cents=0, total_earned_cents=0, total_paid_out_cents=0)
        self.session.add(wallet)
        await self.session.flush()
        return wallet

    async def approve_reward(self, reward_id: int, admin_id: Optional[int] = None,
                             note: Optional[str] = None) -> ReferralReward:
        reward = await self._lock_reward(reward_id)
        if reward.status == RewardStatus.APPROVED:
            return reward

        wallet = await self.get_or_create_wallet(reward.referrer_id, lock=True)
        reward.status = RewardStatus.APPROVED
        reward.approved_at = datetime.now(UTC)
        reward.cancelled_at = None
        wallet.total_earned_cents += reward.amount_cents
        self._add_transaction(
            wallet,
            amount_cents=reward.amount_cents,
            transaction_type=WalletTransactionType.REWARD_CREDIT,
            reward_id=reward.id,
            admin_id=admin_id,
            note=note or f"Reward for purchase {reward.external_purchase_id}",
        )
        await self.session.commit()
        await self.session.refresh(reward)

        logger.info("Referral reward approved", extra={
            "reward_id": reward.id,
            "referrer_id": reward.referrer_id,
            "amount_cents": reward.amount_cents,
            "admin_id": admin_id,
        })
        return reward

    async def cancel_reward(self, reward_id: int, admin_id: Optional[int] = None,
                            note: Optional[str] = None) -> ReferralReward:
        reward = await self._lock_reward(reward_id)
        if reward.status == RewardStatus.CANCELLED:
            return reward

        if reward.status == RewardStatus.APPROVED:
            wallet = await self.get_or_create_wallet(reward.referrer_id, lock=True)
            wallet.total_earned_cents -= reward.amount_cents
            self._add_transaction(
                wallet,
                amount_cents=-reward.amount_cents,
                transaction_type=WalletTransactionType.REWARD_REVERSAL,
                reward_id=reward.id,
                admin_id=admin_id,
                note=note or f"Reversal of reward for purchase {reward.external_purchase_id}",
            )

        reward.status = RewardStatus.CANCELLED
        reward.cancelled_at = datetime.now(UTC)
        await self.session.commit()
        await self.session.refresh(reward)

        logger.info("Referral reward cancelled", extra={
            "reward_id": reward.id,
            "referrer_id": reward.referrer_id,
            "admin_id": admin_id,
        })
        return reward

    async def payout(
            self,
            user_id: int,
            amount_cents: int,
            admin_id: int,
            note: Optional[str] = None,
            external_reference: Optional[str] = None,
    ) -> WalletTransaction:
        wallet = await self.get_or_create_wallet(user_id, lock=True)
        if amount_cents > wallet.balance_cents:
            detail = f"Payout {amount_cents} exceeds wallet balance {wallet.balance_cents}"
            await self.session.rollback()
            raise InsufficientWalletBalanceProblem(detail=detail)

        wallet.total_paid_out_cents += amount_cents
        transaction = self._add_transaction(
            wallet,
            amount_cents=-amount_cents,
            transaction_type=WalletTransactionType.PAYOUT,
            admin_id=admin_id,
            note=note,
            external_reference=external_reference,
        )
        await self.session.commit()
        await self.session.refresh(transaction)

        logger.info("Referral wallet payout", extra={
            "user_id": user_id,
            "amount_cents": amount_cents,
            "admin_id": admin_id,
        })
        return transaction

    async def adjust(self, user_id: int, amount_cents: int, admin_id: int, note: str) -> WalletTransaction:
        wallet = await self.get_or_create_wallet(user_id, lock=True)
        if wallet.balance_cents + amount_cents < 0:
            detail = f"Adjustment {amount_cents} would make wallet balance negative ({wallet.balance_cents})"
            await self.session.rollback()
            raise InsufficientWalletBalanceProblem(detail=detail)

        transaction = self._add_transaction(
            wallet,
            amount_cents=amount_cents,
            transaction_type=WalletTransactionType.ADJUSTMENT,
            admin_id=admin_id,
            note=note,
        )
        await self.session.commit()
        await self.session.refresh(transaction)

        logger.info("Referral wallet adjustment", extra={
            "user_id": user_id,
            "amount_cents": amount_cents,
            "admin_id": admin_id,
        })
        return transaction

    async def _lock_reward(self, reward_id: int) -> ReferralReward:
        reward = await self.reward_service.get_for_update(reward_id)
        if not reward:
            raise NotFoundProblem(detail=f"Reward {reward_id} not found")
        return reward

    def _add_transaction(
            self,
            wallet: ReferralWallet,
            amount_cents: int,
            transaction_type: WalletTransactionType,
            reward_id: Optional[int] = None,
            admin_id: Optional[int] = None,
            note: Optional[str] = None,
            external_reference: Optional[str] = None,
    ) -> WalletTransaction:
        wallet.balance_cents += amount_cents
        transaction = WalletTransaction(
            wallet_id=wallet.id,
            type=transaction_type,
            amount_cents=amount_cents,
            balance_after_cents=wallet.balance_cents,
            reward_id=reward_id,
            created_by_user_id=admin_id,
            note=note,
            external_reference=external_reference,
        )
        self.session.add(transaction)
        return transaction
