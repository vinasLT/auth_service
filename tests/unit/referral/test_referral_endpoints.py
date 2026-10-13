from datetime import datetime, UTC

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from config import Permissions, settings
from database.models import ReferralVisit, ReferralReward, Referral
from database.models.referral_reward import RewardStatus
from services.rabbit_service.routing_keys import ReferralPublishRoutingKeys
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
    if status == RewardStatus.APPROVED:
        reward.status = RewardStatus.APPROVED
        reward.approved_at = datetime.now(UTC)
    session.add(reward)
    await session.commit()
    await session.refresh(reward)
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

    async def test_me_returns_link_and_stats(self, client: AsyncClient, login_as, referral_data):
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
            "pending_cents": REWARD,
            "currency": settings.REFERRAL_CURRENCY,
        }
        assert "wallet" not in data

    async def test_me_generates_missing_code(self, client: AsyncClient, session, login_as):
        legacy = await create_user(session)
        login_as(legacy, [Permissions.REFERRAL_READ_OWN])

        response = await client.get("v1/private/referral/me")

        assert response.status_code == 200
        assert len(response.json()["referral_code"]) == 8
        assert response.json()["stats"]["visits"] == 0
        assert response.json()["stats"]["pending_cents"] == 0

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
        assert data["rewards_approved_cents"] == REWARD
        assert "total_wallet_balance_cents" not in data

    async def test_admin_endpoints_require_permission(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], [Permissions.REFERRAL_READ_OWN])

        assert (await client.get("v1/private/referral/admin/stats")).status_code == 403
        assert (await client.post(
            f"v1/private/referral/admin/rewards/{referral_data['pending'].id}/approve"
        )).status_code == 403

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
        assert "balance_cents" not in row

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

        assert detail.status_code == 200
        assert detail.json()["stats"]["registrations"] == 2
        assert detail.json()["stats"]["pending_cents"] == REWARD
        assert "wallet" not in detail.json()
        assert bidder_detail.json()["referred_by_uuid"] == referrer_uuid
        assert referrals.json()["count"] == 3
        assert {r["email"] for r in referrals.json()["data"]} >= {"unverified@mail.com"}
        assert rewards.json()["count"] == 2
        assert rewards.json()["data"][0]["referred_user_uuid"] == bidder_uuid

    async def test_admin_unknown_user(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)

        response = await client.get("v1/private/referral/admin/users/unknown-uuid")

        assert response.status_code == 404

    async def test_manual_approve_and_cancel_publish_events(self, client: AsyncClient, login_as, referral_data,
                                                            mock_rabbit_mq):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)
        reward_id = referral_data["pending"].id

        approved = await client.post(f"v1/private/referral/admin/rewards/{reward_id}/approve")
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

        cancelled = await client.post(f"v1/private/referral/admin/rewards/{reward_id}/cancel",
                                      json={"note": "purchase refunded"})
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"

        published = [call.args for call in mock_rabbit_mq.publish.await_args_list]
        assert published[0][0] == ReferralPublishRoutingKeys.REWARD_APPROVED.value
        assert published[0][1]["reward_id"] == reward_id
        assert published[0][1]["referrer_uuid"] == referral_data["referrer"].uuid_key
        assert published[0][1]["admin_uuid"] == referral_data["admin"].uuid_key
        assert published[0][1]["note"] is None
        assert published[1][0] == ReferralPublishRoutingKeys.REWARD_CANCELLED.value
        assert published[1][1]["note"] == "purchase refunded"
        assert published[1][1]["admin_uuid"] == referral_data["admin"].uuid_key

        pending_rewards = await client.get("v1/private/referral/admin/rewards", params={"status": "pending"})
        assert pending_rewards.json()["count"] == 0

    async def test_approve_unknown_reward(self, client: AsyncClient, login_as, referral_data):
        login_as(referral_data["admin"], ADMIN_PERMISSIONS)

        response = await client.post("v1/private/referral/admin/rewards/9999/approve")

        assert response.status_code == 404
