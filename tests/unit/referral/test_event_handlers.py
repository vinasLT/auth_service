from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database.models import Referral, ReferralReward
from database.models.referral_reward import RewardStatus
from services.rabbit_service.routing_keys import ReferralPublishRoutingKeys, RoutingKeys
from services.referral.event_handlers import ReferralEventHandler, UnknownEventError
from tests.unit.referral.conftest import create_user, create_referred_user

BID = RoutingKeys.BID_PLACED
CREATED = RoutingKeys.PURCHASE_CREATED
PAID = RoutingKeys.PURCHASE_PAID
CANCELLED = RoutingKeys.PURCHASE_CANCELLED
APPROVED_KEY = ReferralPublishRoutingKeys.REWARD_APPROVED.value
CANCELLED_KEY = ReferralPublishRoutingKeys.REWARD_CANCELLED.value


async def _reward(session: AsyncSession, purchase_id: str) -> ReferralReward | None:
    return (await session.execute(
        select(ReferralReward)
        .where(ReferralReward.external_purchase_id == purchase_id)
        .execution_options(populate_existing=True)
    )).scalar_one_or_none()


def _handler(session: AsyncSession) -> tuple[ReferralEventHandler, AsyncMock]:
    publisher = AsyncMock()
    return ReferralEventHandler(session, publisher), publisher


def _published(publisher: AsyncMock) -> list[tuple[str, dict]]:
    return [call.args for call in publisher.publish.await_args_list]


@pytest_asyncio.fixture
async def referral_pair(session: AsyncSession):
    referrer = await create_user(session, referral_code="EVENTREF")
    referred = await create_referred_user(session, referrer)
    return referrer, referred


@pytest.mark.asyncio
class TestReferralEventHandler:

    async def test_bid_placed_updates_referral(self, session, referral_pair):
        _, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(BID, {"user_uuid": referred.uuid_key, "bid_id": 1, "lot_id": 77})
        await handler.handle(BID, {"user_uuid": referred.uuid_key, "bid_id": 2})

        referral = (await session.execute(
            select(Referral).where(Referral.referred_user_id == referred.id).execution_options(populate_existing=True)
        )).scalar_one()
        assert referral.bids_count == 2
        assert referral.first_bid_at is not None
        publisher.publish.assert_not_awaited()

    async def test_events_for_not_referred_user_are_ignored(self, session):
        user = await create_user(session)
        handler, publisher = _handler(session)

        await handler.handle(BID, {"user_uuid": user.uuid_key})
        await handler.handle(PAID, {"user_uuid": user.uuid_key, "purchase_id": "p-none"})

        assert await _reward(session, "p-none") is None
        publisher.publish.assert_not_awaited()

    async def test_created_then_paid_publishes_approved(self, session, referral_pair):
        referrer, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(CREATED, {"user_uuid": referred.uuid_key, "purchase_id": "p-1", "vin": "VIN1"})
        reward = await _reward(session, "p-1")
        assert reward.status == RewardStatus.PENDING
        assert reward.amount_cents == settings.REFERRAL_REWARD_AMOUNT_CENTS
        publisher.publish.assert_not_awaited()

        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-1"})

        reward = await _reward(session, "p-1")
        assert reward.status == RewardStatus.APPROVED
        assert reward.approved_at is not None
        routing_key, payload = _published(publisher)[0]
        assert routing_key == APPROVED_KEY
        assert payload["reward_id"] == reward.id
        assert payload["referrer_uuid"] == referrer.uuid_key
        assert payload["amount_cents"] == settings.REFERRAL_REWARD_AMOUNT_CENTS
        assert payload["currency"] == settings.REFERRAL_CURRENCY
        assert payload["external_purchase_id"] == "p-1"
        assert payload["admin_uuid"] is None
        assert payload["note"] is None

    async def test_paid_without_created_republishes_on_duplicate(self, session, referral_pair):
        referrer, referred = referral_pair
        handler, publisher = _handler(session)
        payload = {"user_uuid": referred.uuid_key, "purchase_id": "p-2"}

        await handler.handle(PAID, payload)
        await handler.handle(PAID, payload)
        await handler.handle(CREATED, payload)

        reward = await _reward(session, "p-2")
        assert reward.status == RewardStatus.APPROVED
        published = _published(publisher)
        assert len(published) == 2
        assert [item[0] for item in published] == [APPROVED_KEY, APPROVED_KEY]
        assert published[0][1]["reward_id"] == reward.id
        assert published[1][1]["referrer_uuid"] == referrer.uuid_key

    async def test_every_purchase_publishes_its_own_event(self, session, referral_pair):
        _, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-a"})
        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-b"})

        published = _published(publisher)
        assert [item[1]["external_purchase_id"] for item in published] == ["p-a", "p-b"]
        assert published[0][1]["reward_id"] != published[1][1]["reward_id"]

    async def test_cancel_pending_reward_publishes_cancelled(self, session, referral_pair):
        _, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(CREATED, {"user_uuid": referred.uuid_key, "purchase_id": "p-3"})
        await handler.handle(CANCELLED, {"user_uuid": referred.uuid_key, "purchase_id": "p-3", "reason": "unpaid"})
        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-3"})

        reward = await _reward(session, "p-3")
        assert reward.status == RewardStatus.CANCELLED
        routing_key, payload = _published(publisher)[0]
        assert routing_key == CANCELLED_KEY
        assert payload["reward_id"] == reward.id
        assert payload["note"] == "unpaid"
        assert len(_published(publisher)) == 1

    async def test_cancel_before_created_blocks_later_reward(self, session, referral_pair):
        _, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(CANCELLED, {"user_uuid": referred.uuid_key, "purchase_id": "p-4"})
        await handler.handle(CREATED, {"user_uuid": referred.uuid_key, "purchase_id": "p-4"})

        reward = await _reward(session, "p-4")
        assert reward.status == RewardStatus.CANCELLED
        assert reward.cancelled_at is not None
        publisher.publish.assert_not_awaited()

    async def test_cancel_after_approval_is_left_for_admin_review(self, session, referral_pair):
        _, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-5"})
        await handler.handle(CANCELLED, {"user_uuid": referred.uuid_key, "purchase_id": "p-5"})

        assert (await _reward(session, "p-5")).status == RewardStatus.APPROVED
        assert [item[0] for item in _published(publisher)] == [APPROVED_KEY]

    async def test_invalid_payload_raises_validation_error(self, session):
        handler, _ = _handler(session)
        with pytest.raises(ValidationError):
            await handler.handle(PAID, {"user_uuid": "someone"})

    async def test_unknown_routing_key(self, session):
        handler, _ = _handler(session)
        with pytest.raises(UnknownEventError):
            await handler.handle("auction.unknown", {"user_uuid": "someone"})
