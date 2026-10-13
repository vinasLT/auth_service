from datetime import datetime, UTC
from typing import Optional

from rfc9457 import NotFoundProblem
from sqlalchemy.ext.asyncio import AsyncSession

from core.logger import logger
from database.crud.referral_reward import ReferralRewardService
from database.crud.user import UserService
from database.models import ReferralReward
from database.models.referral_reward import RewardStatus
from services.rabbit_service.routing_keys import ReferralPublishRoutingKeys
from services.rabbit_service.service import RabbitMQPublisher


class RewardService:
    def __init__(self, session: AsyncSession, publisher: RabbitMQPublisher):
        self.session = session
        self.publisher = publisher
        self.reward_service = ReferralRewardService(session)
        self.user_service = UserService(session)

    async def approve_reward(self, reward_id: int, admin_uuid: Optional[str] = None,
                             note: Optional[str] = None) -> ReferralReward:
        reward = await self._lock_reward(reward_id)
        if reward.status != RewardStatus.APPROVED:
            reward.status = RewardStatus.APPROVED
            reward.approved_at = datetime.now(UTC)
            reward.cancelled_at = None
            await self.session.commit()
            await self.session.refresh(reward)

        await self._publish(ReferralPublishRoutingKeys.REWARD_APPROVED, reward, admin_uuid, note)
        logger.info("Referral reward approved", extra={
            "reward_id": reward.id,
            "referrer_id": reward.referrer_id,
            "amount_cents": reward.amount_cents,
            "admin_uuid": admin_uuid,
        })
        return reward

    async def cancel_reward(self, reward_id: int, admin_uuid: Optional[str] = None,
                            note: Optional[str] = None) -> ReferralReward:
        reward = await self._lock_reward(reward_id)
        if reward.status != RewardStatus.CANCELLED:
            reward.status = RewardStatus.CANCELLED
            reward.cancelled_at = datetime.now(UTC)
            await self.session.commit()
            await self.session.refresh(reward)

        await self._publish(ReferralPublishRoutingKeys.REWARD_CANCELLED, reward, admin_uuid, note)
        logger.info("Referral reward cancelled", extra={
            "reward_id": reward.id,
            "referrer_id": reward.referrer_id,
            "admin_uuid": admin_uuid,
        })
        return reward

    async def _lock_reward(self, reward_id: int) -> ReferralReward:
        reward = await self.reward_service.get_for_update(reward_id)
        if not reward:
            raise NotFoundProblem(detail=f"Reward {reward_id} not found")
        return reward

    async def _publish(self, routing_key: ReferralPublishRoutingKeys, reward: ReferralReward,
                       admin_uuid: Optional[str], note: Optional[str]) -> None:
        referrer = await self.user_service.get(reward.referrer_id)
        if referrer is None:
            raise NotFoundProblem(detail=f"Referrer {reward.referrer_id} not found")
        await self.publisher.publish(routing_key.value, {
            "reward_id": reward.id,
            "referrer_uuid": referrer.uuid_key,
            "amount_cents": reward.amount_cents,
            "currency": reward.currency,
            "external_purchase_id": reward.external_purchase_id,
            "admin_uuid": admin_uuid,
            "note": note,
        })
