from datetime import datetime, UTC

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from config import Permissions, settings
from database.models import ReferralVisit, ReferralReward, Referral
from database.models.referral_reward import RewardStatus
from services.referral.wallet_service import WalletService
from tests.unit.referral.conftest import create_user, create_referred_user

REWARD = settings.REFERRAL_REWARD_AMOUNT_CENTS
ADMIN_PERMISSIONS = [Permissions.REFERRAL_READ_ALL, Permissions.REFERRAL_WRITE_ALL]


async def _add_reward(session: AsyncSession, referrer, referred, purchase_id: str,
                      status: RewardStatus = RewardStatus.PENDING) -> ReferralReward:
    reward = ReferralReward(
        referrer_id=referrer.id,
        referred_user_id=referred.id,
        external_purchase_id=purchase_id,
        amount_cents=REWARD,
        currency=settings.REFERRAL_CURRENCY,
        status=RewardStatus.PENDING,
    )
    session.add(reward)
    await session.commit()
    if status == RewardStatus.APPROVED:
        await WalletService(session).approve_reward(reward.id)
    return reward


@pytest_asyncio.fixture
async def referral_data(session: AsyncSession):
    referrer = await create_user(session, referral_code="STATSREF", first_name="Ref", email="referrer@mail.com")
    bidder = await create_referred_user(session, referrer, first_name="Bidder", last_name="Smith",
                                        email="bidder@mail.com")
    await create_referred_user(session, referrer, email="quiet@mail.com")
    await create_referred_user(session, referrer, email="unverified@mail.com", email_verified=False)

    for visitor in ("v1", "v2", "v3", "v4"):
        session.add(ReferralVisit(referrer_id=referrer.id, visitor_id=visitor))
    await session.commit()

    await session.execute(
        update(Referral).where(Referral.referred_user_id == bidder.id)
        .values(bids_count=3, first_bid_at=datetime.now(UTC))
    )
    await session.commit()

    await _add_reward(session, referrer, bidder, "purchase-paid", RewardStatus.APPROVED)
    pending = await _add_reward(session, referrer, bidder, "purchase-pending")
    admin = await create_user(session, email="admin@mail.com")
    return {"referrer": referrer, "bidder": bidder, "pending": pending, "admin": admin}


@pytest.mark.asyncio
class TestMyReferralEndpoints:

    async def test_me_returns_link_stats_and_wallet(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["referrer"], [Permissions.REFERRAL_READ_OWN])

        response = await client.get("v1/private/referral/me")

        assert response.status_code == 200
        data = response.json()
        assert data["referral_code"] == "STATSREF"
        assert data["referral_link"] == f"{settings.REFERRAL_BASE_URL}STATSREF"
        assert data["stats"] == {
            "visits": 4,
            "registrations": 2,
            "users_with_bids": 1,
            "purchases_pending": 1,
            "purchases_paid": 1,
        }
        assert data["wallet"] == {
            "balance_cents": REWARD,
            "pending_cents": REWARD,
            "total_earned_cents": REWARD,
            "total_paid_out_cents": 0,
            "currency": settings.REFERRAL_CURRENCY,
        }

    async def test_me_generates_missing_code(self, client: AsyncClient, session, login_as):
        legacy = await create_user(session)
        login_as(legacy, [Permissions.REFERRAL_READ_OWN])

        response = await client.get("v1/private/referral/me")

        assert response.status_code == 200
        assert len(response.json()["referral_code"]) == 8
        assert response.json()["stats"]["visits"] == 0
        assert response.json()["wallet"]["balance_cents"] == 0

    async def test_me_requires_permission(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["referrer"], [])

        response = await client.get("v1/private/referral/me")

        assert response.status_code == 403

    async def test_my_referrals_are_masked_and_verified_only(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["referrer"], [Permissions.REFERRAL_READ_OWN])

        response = await client.get("v1/private/referral/me/referrals", params={"size": 10})

        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        emails = {item["email"] for item in body["data"]}
        assert emails == {"bi***@mail.com", "qu***@mail.com"}
        bidder = next(item for item in body["data"] if item["email"] == "bi***@mail.com")
        assert bidder["last_name"] == "S."
        assert bidder["has_bid"] is True
        assert bidder["purchases_paid"] == 1
        assert bidder["purchases_pending"] == 1

    async def test_my_rewards_filter(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["referrer"], [Permissions.REFERRAL_READ_OWN])

        response = await client.get("v1/private/referral/me/rewards", params={"status": "pending"})

        assert response.status_code == 200
        assert [r["external_purchase_id"] for r in response.json()["data"]] == ["purchase-pending"]

    async def test_my_transactions(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["referrer"], [Permissions.REFERRAL_READ_OWN])

        response = await client.get("v1/private/referral/me/transactions")

        assert response.status_code == 200
        items = response.json()["data"]
        assert len(items) == 1
        assert items[0]["type"] == "reward_credit"
        assert items[0]["amount_cents"] == REWARD


@pytest.mark.asyncio
class TestAdminReferralEndpoints:

    async def test_admin_stats(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)

        response = await client.get("v1/private/referral/admin/stats")

        assert response.status_code == 200
        data = response.json()
        assert data["total_visits"] == 4
        assert data["total_registrations"] == 2
        assert data["total_users_with_bids"] == 1
        assert data["rewards_pending_count"] == 1
        assert data["rewards_pending_cents"] == REWARD
        assert data["rewards_approved_count"] == 1
        assert data["total_wallet_balance_cents"] == REWARD

    async def test_admin_endpoints_require_permission(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], [Permissions.REFERRAL_READ_OWN])
        referrer_uuid = referral_data["referrer"].uuid_key

        assert (await client.get("v1/private/referral/admin/stats")).status_code == 403
        assert (await client.post(f"v1/private/referral/admin/users/{referrer_uuid}/payouts",
                                  json={"amount_cents": 100})).status_code == 403

    async def test_payout_requires_write_permission(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], [Permissions.REFERRAL_READ_ALL])
        referrer_uuid = referral_data["referrer"].uuid_key

        response = await client.post(f"v1/private/referral/admin/users/{referrer_uuid}/payouts",
                                     json={"amount_cents": 100})

        assert response.status_code == 403

    async def test_referrers_list(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)

        response = await client.get("v1/private/referral/admin/referrers", params={"sort_by": "visits"})

        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        row = body["data"][0]
        assert row["user_uuid"] == referral_data["referrer"].uuid_key
        assert row["visits"] == 4
        assert row["registrations"] == 2
        assert row["purchases_paid"] == 1
        assert row["balance_cents"] == REWARD

    async def test_referrers_search(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)

        found = await client.get("v1/private/referral/admin/referrers", params={"search": "statsref"})
        missing = await client.get("v1/private/referral/admin/referrers", params={"search": "nobody"})

        assert found.json()["count"] == 1
        assert missing.json()["count"] == 0

    async def test_admin_user_detail_and_lists(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)
        referrer_uuid = referral_data["referrer"].uuid_key
        bidder_uuid = referral_data["bidder"].uuid_key

        detail = await client.get(f"v1/private/referral/admin/users/{referrer_uuid}")
        bidder_detail = await client.get(f"v1/private/referral/admin/users/{bidder_uuid}")
        referrals = await client.get(f"v1/private/referral/admin/users/{referrer_uuid}/referrals",
                                     params={"size": 10})
        rewards = await client.get(f"v1/private/referral/admin/users/{referrer_uuid}/rewards")
        transactions = await client.get(f"v1/private/referral/admin/users/{referrer_uuid}/transactions")

        assert detail.status_code == 200
        assert detail.json()["stats"]["registrations"] == 2
        assert bidder_detail.json()["referred_by_uuid"] == referrer_uuid
        assert referrals.json()["count"] == 3
        assert {r["email"] for r in referrals.json()["data"]} >= {"unverified@mail.com"}
        assert rewards.json()["count"] == 2
        assert rewards.json()["data"][0]["referred_user_uuid"] == bidder_uuid
        assert transactions.json()["count"] == 1

    async def test_admin_unknown_user(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)

        response = await client.get("v1/private/referral/admin/users/unknown-uuid")

        assert response.status_code == 404

    async def test_payout_deducts_wallet(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)
        referrer_uuid = referral_data["referrer"].uuid_key

        response = await client.post(
            f"v1/private/referral/admin/users/{referrer_uuid}/payouts",
            json={"amount_cents": 4000, "note": "bank transfer", "external_reference": "TX-1"},
        )

        assert response.status_code == 201
        data = response.json()
        assert data["type"] == "payout"
        assert data["amount_cents"] == -4000
        assert data["balance_after_cents"] == REWARD - 4000
        assert data["external_reference"] == "TX-1"
        assert data["created_by_user_id"] == referral_data["admin"].id

        wallet = (await client.get(f"v1/private/referral/admin/users/{referrer_uuid}")).json()["wallet"]
        assert wallet["balance_cents"] == REWARD - 4000
        assert wallet["total_paid_out_cents"] == 4000
        assert wallet["total_earned_cents"] == REWARD

    async def test_payout_over_balance_is_rejected(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)
        referrer_uuid = referral_data["referrer"].uuid_key

        response = await client.post(f"v1/private/referral/admin/users/{referrer_uuid}/payouts",
                                     json={"amount_cents": REWARD + 1})

        assert response.status_code == 400
        assert response.json()["type"] == "insufficient-wallet-balance"

    @pytest.mark.parametrize("amount", [0, -100])
    async def test_payout_amount_must_be_positive(self, client: AsyncClient, login_as, referral_data, amount):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)
        referrer_uuid = referral_data["referrer"].uuid_key

        response = await client.post(f"v1/private/referral/admin/users/{referrer_uuid}/payouts",
                                     json={"amount_cents": amount})

        assert response.status_code == 422

    async def test_adjustments(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)
        url = f"v1/private/referral/admin/users/{referral_data['referrer'].uuid_key}/adjustments"

        credit = await client.post(url, json={"amount_cents": 500, "note": "bonus"})
        too_much = await client.post(url, json={"amount_cents": -(REWARD + 501), "note": "fix"})
        zero = await client.post(url, json={"amount_cents": 0, "note": "noop"})

        assert credit.status_code == 201
        assert credit.json()["balance_after_cents"] == REWARD + 500
        assert too_much.status_code == 400
        assert zero.status_code == 422

    async def test_manual_approve_and_cancel_with_reversal(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)
        reward_id = referral_data["pending"].id
        referrer_uuid = referral_data["referrer"].uuid_key

        approved = await client.post(f"v1/private/referral/admin/rewards/{reward_id}/approve")
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

        cancelled = await client.post(f"v1/private/referral/admin/rewards/{reward_id}/cancel",
                                      json={"note": "purchase refunded"})
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"

        transactions = (await client.get(
            f"v1/private/referral/admin/users/{referrer_uuid}/transactions", params={"size": 10}
        )).json()["data"]
        assert [t["type"] for t in transactions] == ["reward_reversal", "reward_credit", "reward_credit"]
        assert transactions[0]["balance_after_cents"] == REWARD
        assert transactions[0]["note"] == "purchase refunded"

        pending_rewards = await client.get("v1/private/referral/admin/rewards", params={"status": "pending"})
        assert pending_rewards.json()["count"] == 0

    async def test_approve_unknown_reward(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)

        response = await client.post("v1/private/referral/admin/rewards/9999/approve")

        assert response.status_code == 404
