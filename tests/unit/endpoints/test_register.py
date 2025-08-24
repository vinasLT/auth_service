import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from database.models import User
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

    async def test_if_user_register_but_not_verify_email(self, client, session):
        new_user = UserFactory.build(email_verified=False, phone_verified=False)
        session.add(new_user)
        await session.commit()
        await session.refresh(
            new_user
        )
        payload = {
            "email": new_user.email,
            "phone_number": new_user.phone_number,
            "password": "StrongPass!2",
            "first_name": new_user.first_name,
            "last_name": new_user.last_name,
        }

        response = await client.post("v1/register", json=payload)
        assert response.status_code == 409



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