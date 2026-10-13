from typing import Optional

from rfc9457 import NotFoundProblem
from sqlalchemy.ext.asyncio import AsyncSession

from core.logger import logger
from database.crud.user import UserService
from database.models import ReferralReward
from services.rabbit_service.routing_keys import ReferralPublishRoutingKeys
from services.rabbit_service.service import RabbitMQPublisher


class RewardService:
    def __init__(self, session: AsyncSession, publisher: RabbitMQPublisher):
        self.publisher = publisher
        self.user_service = UserService(session)

    async def notify_reward_confirmed(self, reward: ReferralReward) -> None:
        referrer = await self.user_service.get(reward.referrer_id)
        if referrer is None:
            raise NotFoundProblem(detail=f"Referrer {reward.referrer_id} not found")
        await self.publisher.publish(ReferralPublishRoutingKeys.REWARD_APPROVED.value, {
            "reward_id": reward.id,
            "referrer_uuid": referrer.uuid_key,
            "amount_cents": reward.amount_cents,
            "currency": reward.currency,
            "external_purchase_id": reward.external_purchase_id,
        })
        logger.info("Referral reward confirmed", extra={
            "reward_id": reward.id,
            "referrer_id": reward.referrer_id,
            "amount_cents": reward.amount_cents,
        })
