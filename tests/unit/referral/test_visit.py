from datetime import datetime, UTC, timedelta

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

    async def test_same_visitor_counted_once(self, client: AsyncClient, session: AsyncSession):
        referrer = await create_user(session, referral_code="VISITOR1")

        first = await client.post(self.url, json={"referral_code": "visitor1", "visitor_id": "abc"})
        second = await client.post(self.url, json={"referral_code": "VISITOR1", "visitor_id": "abc"})
        other = await client.post(self.url, json={"referral_code": "VISITOR1", "visitor_id": "xyz"})

        assert first.json()["valid"] is True
        assert first.json()["visit_id"] == second.json()["visit_id"]
        assert other.json()["visit_id"] != first.json()["visit_id"]
        assert await _visits_count(session, referrer.id) == 2

    async def test_fingerprint_fallback_dedupes_within_window(self, client: AsyncClient, session: AsyncSession):
        referrer = await create_user(session, referral_code="FINGERPR")
        headers = {"user-agent": "test-agent", "x-forwarded-for": "10.0.0.1"}

        first = await client.post(self.url, json={"referral_code": "FINGERPR"}, headers=headers)
        second = await client.post(self.url, json={"referral_code": "FINGERPR"}, headers=headers)
        other_ip = await client.post(self.url, json={"referral_code": "FINGERPR"},
                                     headers={**headers, "x-forwarded-for": "10.0.0.2"})

        assert first.json()["visit_id"] == second.json()["visit_id"]
        assert other_ip.json()["visit_id"] != first.json()["visit_id"]
        assert await _visits_count(session, referrer.id) == 2

    async def test_fingerprint_outside_window_is_new_visit(self, client: AsyncClient, session: AsyncSession):
        referrer = await create_user(session, referral_code="OLDVISIT")
        session.add(ReferralVisit(
            referrer_id=referrer.id,
            ip_address="10.0.0.9",
            user_agent="test-agent",
            created_at=datetime.now(UTC) - timedelta(days=2),
        ))
        await session.commit()

        response = await client.post(
            self.url,
            json={"referral_code": "OLDVISIT"},
            headers={"user-agent": "test-agent", "x-forwarded-for": "10.0.0.9"},
        )

        assert response.json()["valid"] is True
        assert await _visits_count(session, referrer.id) == 2
