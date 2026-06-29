import grpc
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, MagicMock, patch

from database.models import User
from tests.factories.token_session_user_factories import UserFactory


@pytest.fixture
def create_manually_url(get_app):
    return get_app.url_path_for("create_new_user")


@pytest.fixture
def mock_account_rpc():
    mock_plan = MagicMock()
    mock_plan.name = "Basic"
    mock_plan.description = "Basic plan"
    mock_plan.bid_power = 100
    mock_plan.price = 0
    mock_plan.max_bid_one_time = 50

    mock_account = MagicMock()
    mock_account.balance = 1000
    mock_account.plan = mock_plan

    mock_client = MagicMock()
    mock_client.get_account_info = AsyncMock(return_value=mock_account)

    mock_context = MagicMock()
    mock_context.__aenter__ = AsyncMock(return_value=mock_client)
    mock_context.__aexit__ = AsyncMock(return_value=None)

    with patch("routers.v1.private.user.AccountRpcClient", return_value=mock_context):
        yield mock_client


def _build_payload(user, password="StrongPass!2"):
    return {
        "email": user.email,
        "phone_number": user.phone_number.lstrip("+").replace("-", "").replace(" ", ""),
        "password": password,
        "first_name": user.first_name,
        "last_name": user.last_name,
    }


@pytest.mark.asyncio
class TestManualUserCreation:

    async def _create_user(self, session, **kwargs):
        user = UserFactory.build(**kwargs)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    async def test_create_manually_success(
        self,
        client: AsyncClient,
        session: AsyncSession,
        create_manually_url: str,
        mock_auth_service,
        mock_account_rpc,
    ):
        new_user = UserFactory.build(phone_number="1234567890")
        payload = _build_payload(new_user)
        mock_auth_service.hash_password.return_value = "hashed_password"

        response = await client.post(create_manually_url, json=payload)
        assert response.status_code == 201

        data = response.json()
        assert data["email"] == payload["email"]
        assert data["phone_number"] == payload["phone_number"]
        assert data["first_name"] == payload["first_name"]
        assert data["last_name"] == payload["last_name"]
        assert data["email_verified"] is True
        assert data["phone_verified"] is True
        assert data["is_created_manually"] is True
        assert "roles" in data
        assert "permissions" in data
        assert data["account"]["balance"] == 1000
        assert data["account"]["plan"]["name"] == "Basic"

        created = await session.get(User, data["id"])
        assert created.password_hash == "hashed_password"
        assert created.email_verified is True
        assert created.phone_verified is True
        assert created.is_created_manually is True

        mock_account_rpc.get_account_info.assert_awaited_once()

    @pytest.mark.parametrize(
        "email_verified,phone_verified,expected_status",
        [
            (False, False, 201),
            (True, False, 409),
            (False, True, 409),
            (True, True, 409),
        ],
    )
    async def test_create_manually_with_existing_verification_states(
        self,
        client: AsyncClient,
        session: AsyncSession,
        create_manually_url: str,
        mock_account_rpc,
        email_verified: bool,
        phone_verified: bool,
        expected_status: int,
    ):
        user = await self._create_user(
            session,
            email="existing@mail.com",
            phone_number="5551234567",
            email_verified=email_verified,
            phone_verified=phone_verified,
        )
        payload = {
            "email": user.email,
            "phone_number": user.phone_number,
            "password": "StrongPass!2",
            "first_name": user.first_name,
            "last_name": user.last_name,
        }
        response = await client.post(create_manually_url, json=payload)
        assert response.status_code == expected_status

        if expected_status == 201:
            data = response.json()
            assert data["email_verified"] is True
            assert data["phone_verified"] is True

    async def test_create_manually_updates_unverified_user_by_email(
        self,
        client: AsyncClient,
        session: AsyncSession,
        create_manually_url: str,
        mock_auth_service,
        mock_account_rpc,
    ):
        existing = await self._create_user(
            session,
            email="pending@mail.com",
            phone_number="1111111111",
            email_verified=False,
            phone_verified=False,
        )
        payload = {
            "email": existing.email,
            "phone_number": "2222222222",
            "password": "StrongPass!2",
            "first_name": "Updated",
            "last_name": "User",
        }
        mock_auth_service.hash_password.return_value = "new_hashed_password"

        response = await client.post(create_manually_url, json=payload)
        assert response.status_code == 201

        data = response.json()
        assert data["id"] == existing.id
        assert data["first_name"] == "Updated"
        assert data["last_name"] == "User"
        assert data["phone_number"] == "2222222222"
        assert data["email_verified"] is True
        assert data["phone_verified"] is True

        await session.refresh(existing)
        assert existing.password_hash == "new_hashed_password"
        assert existing.email_verified is True
        assert existing.phone_verified is True

    async def test_create_manually_updates_unverified_user_by_phone(
        self,
        client: AsyncClient,
        session: AsyncSession,
        create_manually_url: str,
        mock_auth_service,
        mock_account_rpc,
    ):
        existing = await self._create_user(
            session,
            email="old@mail.com",
            phone_number="3333333333",
            email_verified=False,
            phone_verified=False,
        )
        payload = {
            "email": "new@mail.com",
            "phone_number": existing.phone_number,
            "password": "StrongPass!2",
            "first_name": "New",
            "last_name": "Name",
        }
        mock_auth_service.hash_password.return_value = "new_hashed_password"

        response = await client.post(create_manually_url, json=payload)
        assert response.status_code == 201

        data = response.json()
        assert data["id"] == existing.id
        assert data["email"] == "new@mail.com"
        assert data["first_name"] == "New"
        assert data["email_verified"] is True
        assert data["phone_verified"] is True

    async def test_create_manually_invalid_email(self, client: AsyncClient, create_manually_url: str):
        response = await client.post(
            create_manually_url,
            json={
                "email": "invalid-email",
                "password": "StrongPass!2",
                "phone_number": "1234567890",
                "first_name": "Test",
                "last_name": "User",
            },
        )
        assert response.status_code == 422

    async def test_create_manually_weak_password(self, client: AsyncClient, create_manually_url: str):
        response = await client.post(
            create_manually_url,
            json={
                "email": "weak@mail.com",
                "password": "123",
                "phone_number": "1234567890",
                "first_name": "Test",
                "last_name": "User",
            },
        )
        assert response.status_code == 422

    async def test_create_manually_missing_phone_number(self, client: AsyncClient, create_manually_url: str):
        response = await client.post(
            create_manually_url,
            json={
                "email": "missing@mail.com",
                "password": "StrongPass!2",
                "first_name": "Test",
                "last_name": "User",
            },
        )
        assert response.status_code == 422

    async def test_create_manually_account_rpc_error(
        self,
        client: AsyncClient,
        session: AsyncSession,
        create_manually_url: str,
        mock_auth_service,
    ):
        new_user = UserFactory.build(phone_number="9876543210")
        payload = _build_payload(new_user)
        mock_auth_service.hash_password.return_value = "hashed_password"

        rpc_error = grpc.aio.AioRpcError(
            grpc.StatusCode.NOT_FOUND,
            "payment service",
            "account not found",
        )

        mock_client = MagicMock()
        mock_client.get_account_info = AsyncMock(side_effect=rpc_error)
        mock_context = MagicMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_client)
        mock_context.__aexit__ = AsyncMock(return_value=None)

        with patch("routers.v1.private.user.AccountRpcClient", return_value=mock_context):
            response = await client.post(create_manually_url, json=payload)

        assert response.status_code == 400
        assert "account" in response.json()["detail"].lower()
