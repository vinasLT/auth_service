import pytest
from httpx import AsyncClient
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import ReferralVisit
from tests.unit.referral.conftest import create_user


async def _visits_count(session: AsyncSession, referrer_id: int) -> int:
    return await session.scalar(select(func.count(ReferralVisit.id)).where(ReferralVisit.referrer_id == referrer_id))


@pytest.mark.asyncio
class TestReferralVisit:
    url = "v1/referral/visit"

    async def test_unknown_code_is_not_valid(self, client: AsyncClient):
        response = await client.post(self.url, json={"referral_code": "NOPE1234"})

        assert response.status_code == 200
        assert response.json() == {"valid": False, "visit_id": None}
        assert "referral_visitor_id=" in response.headers["set-cookie"]

    async def test_same_visitor_counted_once(self, client: AsyncClient, session: AsyncSession):
        referrer = await create_user(session, referral_code="VISITOR1")

        first = await client.post(self.url, json={"referral_code": "visitor1"})
        second = await client.post(self.url, json={"referral_code": "VISITOR1"})
        visitor_cookie = client.cookies.get("referral_visitor_id")
        client.cookies.clear()
        other = await client.post(self.url, json={"referral_code": "VISITOR1"})

        assert first.json()["valid"] is True
        assert "referral_visitor_id=" in first.headers["set-cookie"]
        assert visitor_cookie
        assert first.json()["visit_id"] == second.json()["visit_id"]
        assert other.json()["visit_id"] != first.json()["visit_id"]
        assert await _visits_count(session, referrer.id) == 2
