import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import User, Referral, ReferralVisit
from tests.unit.referral.conftest import create_user, create_referred_user


def _payload(email: str, phone: str, **extra) -> dict:
    return {
        "email": email,
        "phone_number": phone,
        "password": "StrongPass!2",
        "first_name": "New",
        "last_name": "User",
        **extra,
    }


async def _get_user(session: AsyncSession, email: str) -> User:
    return (await session.execute(select(User).where(User.email == email))).scalar_one()


async def _get_referral(session: AsyncSession, user_id: int) -> Referral | None:
    return (await session.execute(select(Referral).where(Referral.referred_user_id == user_id))).scalar_one_or_none()


@pytest.mark.asyncio
class TestRegistrationAttribution:

    async def test_new_user_gets_referral_code(self, client: AsyncClient, session: AsyncSession):
        response = await client.post("v1/register", json=_payload("plain@mail.com", "4400000001"))

        assert response.status_code == 201
        code = response.json()["referral_code"]
        assert code and len(code) == 8

    async def test_registration_with_valid_code_links_referrer(self, client: AsyncClient, session: AsyncSession):
        referrer = await create_user(session, referral_code="REFCODE2")

        response = await client.post(
            "v1/register", json=_payload("invited@mail.com", "4400000002", referral_code="refcode2")
        )

        assert response.status_code == 201
        user = await _get_user(session, "invited@mail.com")
        assert user.referred_by_id == referrer.id
        referral = await _get_referral(session, user.id)
        assert referral is not None
        assert referral.referrer_id == referrer.id

    async def test_registration_links_visit(self, client: AsyncClient, session: AsyncSession):
        referrer = await create_user(session, referral_code="VISITREF")
        visit = ReferralVisit(referrer_id=referrer.id, visitor_id="visitor-1")
        session.add(visit)
        await session.commit()

        response = await client.post(
            "v1/register",
            json=_payload("visited@mail.com", "4400000003", referral_code="VISITREF", referral_visit_id=visit.id),
        )

        assert response.status_code == 201
        user = await _get_user(session, "visited@mail.com")
        referral = await _get_referral(session, user.id)
        assert referral.visit_id == visit.id
        await session.refresh(visit)
        assert visit.converted_user_id == user.id

    async def test_visit_of_other_referrer_is_ignored(self, client: AsyncClient, session: AsyncSession):
        referrer = await create_user(session, referral_code="OWNERREF")
        other = await create_user(session, referral_code="OTHERREF")
        visit = ReferralVisit(referrer_id=other.id, visitor_id="visitor-2")
        session.add(visit)
        await session.commit()

        response = await client.post(
            "v1/register",
            json=_payload("mixed@mail.com", "4400000004", referral_code="OWNERREF", referral_visit_id=visit.id),
        )

        assert response.status_code == 201
        user = await _get_user(session, "mixed@mail.com")
        referral = await _get_referral(session, user.id)
        assert referral.referrer_id == referrer.id
        assert referral.visit_id is None

    async def test_invalid_code_does_not_fail_registration(self, client: AsyncClient, session: AsyncSession):
        response = await client.post(
            "v1/register", json=_payload("nocode@mail.com", "4400000005", referral_code="UNKNOWN9")
        )

        assert response.status_code == 201
        user = await _get_user(session, "nocode@mail.com")
        assert user.referred_by_id is None
        assert await _get_referral(session, user.id) is None

    async def test_inactive_referrer_is_ignored(self, client: AsyncClient, session: AsyncSession):
        await create_user(session, referral_code="INACTIVE", is_active=False)

        response = await client.post(
            "v1/register", json=_payload("inactive@mail.com", "4400000006", referral_code="INACTIVE")
        )

        assert response.status_code == 201
        user = await _get_user(session, "inactive@mail.com")
        assert user.referred_by_id is None

    async def test_unverified_user_reregistering_gets_attributed(self, client: AsyncClient, session: AsyncSession):
        referrer = await create_user(session, referral_code="LATEREF2")
        pending = await create_user(session, email="pending@mail.com", email_verified=False, phone_verified=False)

        response = await client.post(
            "v1/register",
            json=_payload("pending@mail.com", "4400000007", referral_code="LATEREF2"),
        )

        assert response.status_code == 201
        await session.refresh(pending)
        assert pending.referred_by_id == referrer.id
        assert pending.referral_code is not None

    async def test_self_referral_is_ignored(self, client: AsyncClient, session: AsyncSession):
        await create_user(session, email="self@mail.com", referral_code="SELFCODE",
                          email_verified=False, phone_verified=False)

        response = await client.post(
            "v1/register", json=_payload("self@mail.com", "4400000008", referral_code="SELFCODE")
        )

        assert response.status_code == 201
        user = await _get_user(session, "self@mail.com")
        assert user.referred_by_id is None

    async def test_existing_referrer_is_not_overwritten(self, client: AsyncClient, session: AsyncSession):
        first = await create_user(session, referral_code="FIRSTREF")
        await create_user(session, referral_code="SECONDRF")
        pending = await create_referred_user(session, first, email="twice@mail.com",
                                             email_verified=False, phone_verified=False)

        response = await client.post(
            "v1/register", json=_payload("twice@mail.com", "4400000009", referral_code="SECONDRF")
        )

        assert response.status_code == 201
        await session.refresh(pending)
        assert pending.referred_by_id == first.id
