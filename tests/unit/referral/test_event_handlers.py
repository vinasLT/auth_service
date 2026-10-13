from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database.models import Referral, ReferralReward
from services.rabbit_service.routing_keys import ReferralPublishRoutingKeys, RoutingKeys
from services.referral.event_handlers import ReferralEventHandler, UnknownEventError
from tests.unit.referral.conftest import create_user, create_referred_user

BID = RoutingKeys.BID_PLACED
PAID = RoutingKeys.BID_PAID
APPROVED_KEY = ReferralPublishRoutingKeys.REWARD_APPROVED.value


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


def _bid_paid(user_uuid: str, bid_id: int, **extra) -> dict:
    return {
        "user_uuid": user_uuid,
        "bid_id": bid_id,
        "lot_id": 77,
        "auction": "copart",
        "bid_amount": 1500,
        "final_bid": 1600,
        "vehicle_title": "2018 Honda Civic",
        "vehicle_image": "https://img.example/car.jpg",
        "auction_date": "2026-10-01T12:00:00",
        "vin": "VIN1",
        "bid_status": "won",
        "payment_status": "paid",
        "account_blocked": False,
        "email": "bidder@mail.com",
        "phone_number": "32452937423",
        **extra,
    }


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

    async def test_bid_paid_creates_reward_and_publishes(self, session, referral_pair):
        referrer, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(PAID, _bid_paid(referred.uuid_key, 41))

        reward = await _reward(session, "41")
        assert reward is not None
        assert reward.amount_cents == settings.REFERRAL_REWARD_AMOUNT_CENTS
        assert reward.currency == settings.REFERRAL_CURRENCY
        assert reward.lot_id == "77"
        assert reward.vin == "VIN1"
        routing_key, payload = _published(publisher)[0]
        assert routing_key == APPROVED_KEY
        assert payload == {
            "reward_id": reward.id,
            "referrer_uuid": referrer.uuid_key,
            "amount_cents": settings.REFERRAL_REWARD_AMOUNT_CENTS,
            "currency": settings.REFERRAL_CURRENCY,
            "external_purchase_id": "41",
        }

    async def test_duplicate_bid_paid_keeps_one_reward_and_republishes(self, session, referral_pair):
        _, referred = referral_pair
        handler, publisher = _handler(session)
        payload = _bid_paid(referred.uuid_key, 42)

        await handler.handle(PAID, payload)
        await handler.handle(PAID, payload)

        reward = await _reward(session, "42")
        published = _published(publisher)
        assert reward is not None
        assert len(published) == 2
        assert [item[0] for item in published] == [APPROVED_KEY, APPROVED_KEY]
        assert published[0][1]["reward_id"] == reward.id
        assert published[1][1]["reward_id"] == reward.id

    async def test_every_paid_bid_publishes_its_own_event(self, session, referral_pair):
        _, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(PAID, _bid_paid(referred.uuid_key, 10))
        await handler.handle(PAID, _bid_paid(referred.uuid_key, 11))

        published = _published(publisher)
        assert [item[1]["external_purchase_id"] for item in published] == ["10", "11"]
        assert published[0][1]["reward_id"] != published[1][1]["reward_id"]

    async def test_events_for_not_referred_user_are_ignored(self, session):
        user = await create_user(session)
        handler, publisher = _handler(session)

        await handler.handle(BID, {"user_uuid": user.uuid_key})
        await handler.handle(PAID, _bid_paid(user.uuid_key, 99))

        assert await _reward(session, "99") is None
        publisher.publish.assert_not_awaited()

    async def test_non_paid_status_is_ignored(self, session, referral_pair):
        _, referred = referral_pair
        handler, publisher = _handler(session)

        await handler.handle(PAID, _bid_paid(referred.uuid_key, 55, payment_status="pending"))

        assert await _reward(session, "55") is None
        publisher.publish.assert_not_awaited()

    async def test_invalid_payload_raises_validation_error(self, session):
        handler, _ = _handler(session)
        with pytest.raises(ValidationError):
            await handler.handle(PAID, {"user_uuid": "someone"})

    async def test_unknown_routing_key(self, session):
        handler, _ = _handler(session)
        with pytest.raises(UnknownEventError):
            await handler.handle("auction.unknown", {"user_uuid": "someone"})
