from datetime import datetime, UTC
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from core.logger import logger
from database.crud.referral import ReferralRecordService
from database.crud.referral_reward import ReferralRewardService
from database.crud.user import UserService
from database.models import Referral, ReferralReward
from database.models.referral_reward import RewardStatus
from database.schemas.referral import ReferralRewardCreate
from schemas.event_schemas.referral import (
    BidPlacedEvent,
    PurchaseCreatedEvent,
    PurchasePaidEvent,
    PurchaseCancelledEvent,
)
from services.rabbit_service.routing_keys import RoutingKeys
from services.rabbit_service.service import RabbitMQPublisher
from services.referral.reward_service import RewardService


class UnknownEventError(Exception):
    pass


class ReferralEventHandler:
    def __init__(self, session: AsyncSession, publisher: RabbitMQPublisher):
        self.session = session
        self.user_service = UserService(session)
        self.referral_record_service = ReferralRecordService(session)
        self.reward_service = ReferralRewardService(session)
        self.reward_actions = RewardService(session, publisher)

    async def handle(self, routing_key: str, payload: dict) -> None:
        handlers = {
            RoutingKeys.BID_PLACED: self.handle_bid_placed,
            RoutingKeys.PURCHASE_CREATED: self.handle_purchase_created,
            RoutingKeys.PURCHASE_PAID: self.handle_purchase_paid,
            RoutingKeys.PURCHASE_CANCELLED: self.handle_purchase_cancelled,
        }
        handler = handlers.get(routing_key)
        if handler is None:
            raise UnknownEventError(f"No handler for routing key '{routing_key}'")
        await handler(payload)

    async def handle_bid_placed(self, payload: dict) -> None:
        event = BidPlacedEvent.model_validate(payload)
        referral = await self._get_referral(event.user_uuid)
        if not referral:
            return
        await self.referral_record_service.register_bid(referral.referred_user_id, event.created_at or datetime.now(UTC))
        logger.info("Referral bid registered", extra={"referred_user_id": referral.referred_user_id,
                                                      "bid_id": event.bid_id})

    async def handle_purchase_created(self, payload: dict) -> None:
        event = PurchaseCreatedEvent.model_validate(payload)
        referral = await self._get_referral(event.user_uuid)
        if not referral:
            return
        await self._get_or_create_reward(referral, event.purchase_id, event.lot_id, event.vin)

    async def handle_purchase_paid(self, payload: dict) -> None:
        event = PurchasePaidEvent.model_validate(payload)
        referral = await self._get_referral(event.user_uuid)
        if not referral:
            return
        reward = await self._get_or_create_reward(referral, event.purchase_id, event.lot_id, event.vin)
        if reward.status == RewardStatus.CANCELLED:
            logger.warning("Paid event for cancelled referral reward, skipping", extra={
                "reward_id": reward.id,
                "purchase_id": event.purchase_id,
            })
            return
        await self.reward_actions.approve_reward(reward.id)

    async def handle_purchase_cancelled(self, payload: dict) -> None:
        event = PurchaseCancelledEvent.model_validate(payload)
        referral = await self._get_referral(event.user_uuid)
        if not referral:
            return
        reward = await self.reward_service.get_by_external_purchase_id(event.purchase_id)
        if reward is None:
            await self._get_or_create_reward(referral, event.purchase_id, status=RewardStatus.CANCELLED)
            return
        if reward.status == RewardStatus.APPROVED:
            logger.warning("Purchase cancelled after referral reward was approved, needs admin review", extra={
                "reward_id": reward.id,
                "purchase_id": event.purchase_id,
                "reason": event.reason,
            })
            return
        await self.reward_actions.cancel_reward(reward.id, note=event.reason)

    async def _get_referral(self, user_uuid: str) -> Optional[Referral]:
        user = await self.user_service.get_user_by_uuid(user_uuid)
        if not user or user.referred_by_id is None:
            return None
        return await self.referral_record_service.get_by_referred_user_id(user.id)

    async def _get_or_create_reward(
            self,
            referral: Referral,
            purchase_id: str,
            lot_id: Optional[str] = None,
            vin: Optional[str] = None,
            status: RewardStatus = RewardStatus.PENDING,
    ) -> ReferralReward:
        reward = await self.reward_service.get_by_external_purchase_id(purchase_id)
        if reward:
            return reward
        try:
            reward = await self.reward_service.create(ReferralRewardCreate(
                referrer_id=referral.referrer_id,
                referred_user_id=referral.referred_user_id,
                external_purchase_id=purchase_id,
                lot_id=lot_id,
                vin=vin,
                amount_cents=settings.REFERRAL_REWARD_AMOUNT_CENTS,
                currency=settings.REFERRAL_CURRENCY,
                status=status,
                cancelled_at=datetime.now(UTC) if status == RewardStatus.CANCELLED else None,
            ))
        except IntegrityError:
            await self.session.rollback()
            reward = await self.reward_service.get_by_external_purchase_id(purchase_id)
            if reward is None:
                raise
            return reward

        logger.info("Referral reward created", extra={
            "reward_id": reward.id,
            "referrer_id": reward.referrer_id,
            "purchase_id": purchase_id,
            "status": reward.status,
        })
        return reward
