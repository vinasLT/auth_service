import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from database.models import User
from scripts.init_db import seed_db
from tests.conftest import engine_test_async
from tests.factories.token_session_user_factories import UserFactory


@pytest.mark.asyncio
class TestUserRegistration:

    async def test_user_already_exists(self, client, session):
        existing_user = UserFactory.build(
            email="test@mail.com",
            phone_number="+1234567890",
            password_hash="test!1Password",
        )
        session.add(existing_user)
        await session.commit()

        response = await client.post("v1/register", json={
            "email": "test@mail.com",
            "password": "test!1Password",
            "phone_number": "1234567890",
            "first_name": "Test",
            "last_name": "User"

        })

        assert response.status_code == 409

    async def _create_user(self, session, **kwargs):
        user = UserFactory.build(**kwargs)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    async def _create_users(self, session, users_data):
        users = []
        for user_kwargs in users_data:
            user = UserFactory.build(**user_kwargs)
            session.add(user)
            users.append(user)

        await session.commit()

        for user in users:
            await session.refresh(user)

        return users

    def _get_registration_payload(self, user, password="StrongPass!2"):
        return {
            "email": user.email,
            "phone_number": user.phone_number,
            "password": password,
            "first_name": user.first_name,
            "last_name": user.last_name,
        }

    async def _register_user(self, client, user, password="StrongPass!2"):
        payload = self._get_registration_payload(user, password)
        return await client.post("v1/register", json=payload)

    @pytest.mark.parametrize("email_verified,phone_verified,expected_status", [
        (False, False, 201),
        (True, False, 409),
        (True, True, 409),
    ])
    async def test_registration_with_different_verification_states(
            self, client, session, email_verified, phone_verified, expected_status
    ):
        user = await self._create_user(
            session,
            email_verified=email_verified,
            phone_verified=phone_verified
        )

        response = await self._register_user(client, user)
        assert response.status_code == expected_status

    async def test_registration_with_shared_unverified_phone(self, client, session):
        users = await self._create_users(session, [
            {"email_verified": False, "phone_verified": False},
            {"email_verified": True, "phone_verified": False, "phone_number": ''}
        ])

        users[1].phone_number = users[0].phone_number
        await session.commit()

        response = await self._register_user(client, users[0])
        assert response.status_code == 201



    async def test_register_success(self, client: AsyncClient, session: AsyncSession, mock_auth_service):
        new_user = UserFactory.build()
        payload = {
            "email": new_user.email,
            "phone_number": new_user.phone_number,
            "password": "StrongPass!2",
            "first_name": new_user.first_name,
            "last_name": new_user.last_name,
        }

        mock_auth_service.hash_password.return_value = "hashed_password"

        response = await client.post("v1/register", json=payload)
        assert response.status_code == 201

        data = response.json()
        assert data["email"] == payload["email"]

        created = await session.get(User, data["id"])
        hashed_password = created.password_hash
        assert hashed_password == "hashed_password"
        assert created.email == payload["email"]

    async def test_register_invalid_email(self, client):
        response = await client.post("v1/register", json={
            "email": "invalid-email",
            "password": "StrongPass!2",
            "phone_number": "+1234567890",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 422

    async def test_register_weak_password(self, client):
        response = await client.post("v1/register", json={
            "email": "weak@mail.com",
            "password": "123",
            "phone_number": "+1234567890",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 422

    async def test_register_missing_phone_number(self, client):
        response = await client.post("v1/register", json={
            "email": "missing@mail.com",
            "password": "StrongPass!2",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 422

    async def test_user_with_same_phone_exists(self, client, session):
        user = UserFactory.build(email="unique@mail.com", phone_number="+1111111111")
        session.add(user)
        await session.commit()

        response = await client.post("v1/register", json={
            "email": "another@mail.com",
            "password": "StrongPass!2",
            "phone_number": "1111111111",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 409

    async def test_register_with_normalized_phone_number(self, client, session):
        user = UserFactory.build(phone_number="+1234567890")
        session.add(user)
        await session.commit()

        response = await client.post("v1/register", json={
            "email": "newuser@mail.com",
            "password": "StrongPass!2",
            "phone_number": "1234567890",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 409

    async def test_register_duplicate_email_case_insensitive(self, client, session):
        user = UserFactory.build(email="Case@Test.com")
        session.add(user)
        await session.commit()

        response = await client.post("v1/register", json={
            "email": "case@test.com",
            "password": "StrongPass!2",
            "phone_number": "+9999999999",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 409

    async def test_register_password_too_short(self, client):
        response = await client.post("v1/register", json={
            "email": "shortpass@mail.com",
            "password": "Short1!",
            "phone_number": "+1234567890",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 422

    async def test_register_soft_deleted_user(self, client, session):
        user = UserFactory.build(email="deleted@mail.com", phone_number="+1234567890", is_active=False)
        session.add(user)
        await session.commit()

        response = await client.post("v1/register", json={
            "email": "deleted@mail.com",
            "password": "StrongPass!2",
            "phone_number": "1234567890",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 409

    async def test_register_with_same_number(self, client, session):
        user = UserFactory.build(phone_number="380634379178")
        session.add(user)
        await session.commit()

        response = await client.post("v1/register", json={
            "email": "deleted@mail.com",
            "password": "StrongPass!2",
            "phone_number": "+380634379178",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 409

    async def test_register_with_same_number_plus_without_plus(self, client, session):
        user_plus = UserFactory.build(phone_number="+380634379178")
        user = UserFactory.build(phone_number="380634379178")
        session.add(user_plus)
        await session.commit()
        session.add(user)
        await session.commit()

        response = await client.post("v1/register", json={
            "email": "deleted@mail.com",
            "password": "StrongPass!2",
            "phone_number": "380634379178",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 500

    async def test_register_with_same_number_plus(self, client, session):
        user_plus = UserFactory.build(phone_number="+380634379178")
        session.add(user_plus)
        await session.commit()

        response = await client.post("v1/register", json={
            "email": "deleted@mail.com",
            "password": "StrongPass!2",
            "phone_number": "380634379178",
            "first_name": "Test",
            "last_name": "User"
        })
        assert response.status_code == 409