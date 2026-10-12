import pytest
import pytest_asyncio
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database.models import Referral, ReferralReward, ReferralWallet, WalletTransaction
from services.rabbit_service.routing_keys import RoutingKeys
from database.models.referral_reward import RewardStatus
from database.models.wallet_transaction import WalletTransactionType
from services.referral.event_handlers import ReferralEventHandler, UnknownEventError
from tests.unit.referral.conftest import create_user, create_referred_user

BID = RoutingKeys.BID_PLACED
CREATED = RoutingKeys.PURCHASE_CREATED
PAID = RoutingKeys.PURCHASE_PAID
CANCELLED = RoutingKeys.PURCHASE_CANCELLED


async def _reward(session: AsyncSession, purchase_id: str) -> ReferralReward | None:
    return (await session.execute(
        select(ReferralReward)
        .where(ReferralReward.external_purchase_id == purchase_id)
        .execution_options(populate_existing=True)
    )).scalar_one_or_none()


async def _wallet(session: AsyncSession, user_id: int) -> ReferralWallet | None:
    return (await session.execute(
        select(ReferralWallet).where(ReferralWallet.user_id == user_id).execution_options(populate_existing=True)
    )).scalar_one_or_none()


async def _transactions(session: AsyncSession, wallet_id: int) -> list[WalletTransaction]:
    return list((await session.execute(
        select(WalletTransaction).where(WalletTransaction.wallet_id == wallet_id).order_by(WalletTransaction.id)
    )).scalars().all())


@pytest_asyncio.fixture
async def referral_pair(session: AsyncSession):
    referrer = await create_user(session, referral_code="EVENTREF")
    referred = await create_referred_user(session, referrer)
    return referrer, referred


@pytest.mark.asyncio
class TestReferralEventHandler:

    async def test_bid_placed_updates_referral(self, session, referral_pair):
        _, referred = referral_pair
        handler = ReferralEventHandler(session)

        await handler.handle(BID, {"user_uuid": referred.uuid_key, "bid_id": 1, "lot_id": 77})
        await handler.handle(BID, {"user_uuid": referred.uuid_key, "bid_id": 2})

        referral = (await session.execute(
            select(Referral).where(Referral.referred_user_id == referred.id).execution_options(populate_existing=True)
        )).scalar_one()
        assert referral.bids_count == 2
        assert referral.first_bid_at is not None

    async def test_events_for_not_referred_user_are_ignored(self, session):
        user = await create_user(session)
        handler = ReferralEventHandler(session)

        await handler.handle(BID, {"user_uuid": user.uuid_key})
        await handler.handle(PAID, {"user_uuid": user.uuid_key, "purchase_id": "p-none"})

        assert await _reward(session, "p-none") is None

    async def test_created_then_paid_credits_wallet(self, session, referral_pair):
        referrer, referred = referral_pair
        handler = ReferralEventHandler(session)

        await handler.handle(CREATED, {"user_uuid": referred.uuid_key, "purchase_id": "p-1", "vin": "VIN1"})
        reward = await _reward(session, "p-1")
        assert reward.status == RewardStatus.PENDING
        assert reward.amount_cents == settings.REFERRAL_REWARD_AMOUNT_CENTS
        assert await _wallet(session, referrer.id) is None

        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-1"})

        reward = await _reward(session, "p-1")
        assert reward.status == RewardStatus.APPROVED
        assert reward.approved_at is not None
        wallet = await _wallet(session, referrer.id)
        assert wallet.balance_cents == settings.REFERRAL_REWARD_AMOUNT_CENTS
        assert wallet.total_earned_cents == settings.REFERRAL_REWARD_AMOUNT_CENTS
        transactions = await _transactions(session, wallet.id)
        assert [t.type for t in transactions] == [WalletTransactionType.REWARD_CREDIT]
        assert transactions[0].balance_after_cents == settings.REFERRAL_REWARD_AMOUNT_CENTS
        assert transactions[0].reward_id == reward.id

    async def test_paid_without_created_and_duplicates_are_idempotent(self, session, referral_pair):
        referrer, referred = referral_pair
        handler = ReferralEventHandler(session)
        payload = {"user_uuid": referred.uuid_key, "purchase_id": "p-2"}

        await handler.handle(PAID, payload)
        await handler.handle(PAID, payload)
        await handler.handle(CREATED, payload)

        assert (await _reward(session, "p-2")).status == RewardStatus.APPROVED
        wallet = await _wallet(session, referrer.id)
        assert wallet.balance_cents == settings.REFERRAL_REWARD_AMOUNT_CENTS
        assert len(await _transactions(session, wallet.id)) == 1

    async def test_every_purchase_is_rewarded(self, session, referral_pair):
        referrer, referred = referral_pair
        handler = ReferralEventHandler(session)

        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-a"})
        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-b"})

        wallet = await _wallet(session, referrer.id)
        assert wallet.balance_cents == 2 * settings.REFERRAL_REWARD_AMOUNT_CENTS
        assert [t.balance_after_cents for t in await _transactions(session, wallet.id)] == [
            settings.REFERRAL_REWARD_AMOUNT_CENTS,
            2 * settings.REFERRAL_REWARD_AMOUNT_CENTS,
        ]

    async def test_cancel_pending_reward(self, session, referral_pair):
        referrer, referred = referral_pair
        handler = ReferralEventHandler(session)

        await handler.handle(CREATED, {"user_uuid": referred.uuid_key, "purchase_id": "p-3"})
        await handler.handle(CANCELLED, {"user_uuid": referred.uuid_key, "purchase_id": "p-3", "reason": "unpaid"})
        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-3"})

        reward = await _reward(session, "p-3")
        assert reward.status == RewardStatus.CANCELLED
        assert await _wallet(session, referrer.id) is None

    async def test_cancel_before_created_blocks_later_reward(self, session, referral_pair):
        _, referred = referral_pair
        handler = ReferralEventHandler(session)

        await handler.handle(CANCELLED, {"user_uuid": referred.uuid_key, "purchase_id": "p-4"})
        await handler.handle(CREATED, {"user_uuid": referred.uuid_key, "purchase_id": "p-4"})

        reward = await _reward(session, "p-4")
        assert reward.status == RewardStatus.CANCELLED
        assert reward.cancelled_at is not None

    async def test_cancel_after_approval_keeps_wallet_untouched(self, session, referral_pair):
        referrer, referred = referral_pair
        handler = ReferralEventHandler(session)

        await handler.handle(PAID, {"user_uuid": referred.uuid_key, "purchase_id": "p-5"})
        await handler.handle(CANCELLED, {"user_uuid": referred.uuid_key, "purchase_id": "p-5"})

        assert (await _reward(session, "p-5")).status == RewardStatus.APPROVED
        assert (await _wallet(session, referrer.id)).balance_cents == settings.REFERRAL_REWARD_AMOUNT_CENTS

    async def test_invalid_payload_raises_validation_error(self, session):
        with pytest.raises(ValidationError):
            await ReferralEventHandler(session).handle(PAID, {"user_uuid": "someone"})

    async def test_unknown_routing_key(self, session):
        with pytest.raises(UnknownEventError):
            await ReferralEventHandler(session).handle("auction.unknown", {"user_uuid": "someone"})
