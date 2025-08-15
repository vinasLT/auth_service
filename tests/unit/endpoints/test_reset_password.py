from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from unittest.mock import Mock
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import FastAPI

from database.models.verification_code import VerificationCodeRoutingKey, Destination
from tests.factories.token_session_user_factories import UserFactory
from tests.factories.verefication_token import VerificationCodeFactory


@pytest.mark.asyncio
class TestResetPasswordByEmail:
    """Test suite for reset password by email endpoint"""

    @pytest.fixture
    def reset_password_url(self, get_app: FastAPI):
        """Fixture to get the reset password URL once"""
        return get_app.url_path_for("reset_password_by_email")

    @pytest_asyncio.fixture
    async def test_user(self, session: AsyncSession):
        """Create and return a test user"""
        user = UserFactory.build(
            email="test@mail.com",
            phone_number="+1234567890"
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    @pytest_asyncio.fixture
    async def verification_code(self, session: AsyncSession, test_user):
        """Create and return a verification code for the test user"""
        code = VerificationCodeFactory.build(
            routing_key=VerificationCodeRoutingKey.PASSWORD_RESET,
            destination=Destination.EMAIL,
            user_id=test_user.id
        )
        session.add(code)
        await session.commit()
        await session.refresh(code)
        return code

    def create_payload(self, email: str = "test@mail.com",
                       code: str = "123456",
                       new_password1: str = "test_passworD!1",
                       new_password2: str = None) -> dict:
        """Helper method to create test payload"""
        if new_password2 is None:
            new_password2 = new_password1

        return {
            'email': email,
            'code': code,
            'new_password1': new_password1,
            'new_password2': new_password2
        }

    async def test_reset_password_success(self, client: AsyncClient, session: AsyncSession,
                                          reset_password_url: str, mock_auth_service,
                                          test_user, verification_code):
        """Test successful password reset"""
        mock_auth_service.verify_password = Mock(return_value=False)
        mock_auth_service.hash_password = Mock(return_value='new_hashed_password')

        payload = self.create_payload(
            email=test_user.email,
            code=verification_code.code
        )

        response = await client.post(reset_password_url, json=payload)

        assert response.status_code == 200
        await session.refresh(test_user)
        assert test_user.password_hash == 'new_hashed_password'
        await session.refresh(verification_code)
        assert verification_code.is_verified == True

    async def test_reset_password_user_not_found(self, client: AsyncClient,
                                                 reset_password_url: str):
        """Test password reset with non-existent user email"""
        payload = self.create_payload(email='nonexistent@mail.com')

        response = await client.post(reset_password_url, json=payload)

        assert response.status_code == 404
        assert response.json()['detail'] == 'User not found'

    async def test_reset_password_invalid_code(self, client: AsyncClient, session: AsyncSession,
                                               reset_password_url: str, test_user, verification_code):
        """Test password reset with invalid verification code"""
        payload = self.create_payload(
            email=test_user.email,
            code='999999'  # Wrong code
        )

        response = await client.post(reset_password_url, json=payload)

        assert response.status_code == 400
        assert response.json()['detail'] == 'Invalid code'

    async def test_reset_password_same_as_old(self, client: AsyncClient, session: AsyncSession,
                                              reset_password_url: str, mock_auth_service):
        """Test password reset with same password as current"""
        user = UserFactory.build(
            email="test@mail.com",
            phone_number="+1234567890",
            password_hash="current_hashed_password"
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        code = VerificationCodeFactory.build(
            routing_key=VerificationCodeRoutingKey.PASSWORD_RESET,
            destination=Destination.EMAIL,
            user_id=user.id
        )
        session.add(code)
        await session.commit()

        # Mock verify_password to return True (passwords match)
        mock_auth_service.verify_password = Mock(return_value=True)

        payload = self.create_payload(
            email=user.email,
            code=code.code,
            new_password1='same_password!S1',
            new_password2 = 'same_password!S1'
        )

        response = await client.post(reset_password_url, json=payload)
        print(response.json())

        assert response.status_code == 400
        assert response.json()['detail'] == 'Password cannot be the same as the old'

    async def test_reset_password_mismatched_passwords(self, client: AsyncClient,
                                                       reset_password_url: str,
                                                       test_user, verification_code):
        """Test password reset with mismatched new passwords"""
        payload = self.create_payload(
            email=test_user.email,
            code=verification_code.code,
            new_password1='test_passworD!1',
            new_password2='different_passworD!2'
        )

        response = await client.post(reset_password_url, json=payload)

        assert response.status_code == 422  # Validation error

    async def test_reset_password_invalid_email_format(self, client: AsyncClient,
                                                       reset_password_url: str):
        """Test password reset with invalid email format"""
        payload = self.create_payload(email='not-an-email')

        response = await client.post(reset_password_url, json=payload)

        assert response.status_code == 422  # Validation error

    @pytest.mark.parametrize("payload_override,description", [
        ({'email': None}, "missing email"),
        ({'code': None}, "missing code"),
        ({'new_password1': None, 'new_password2': None}, "missing passwords"),
    ])
    async def test_reset_password_missing_fields(self, client: AsyncClient,
                                                 reset_password_url: str,
                                                 payload_override: dict,
                                                 description: str):
        """Test password reset with missing required fields"""
        base_payload = self.create_payload()

        # Remove fields based on test case
        for key, value in payload_override.items():
            if value is None:
                base_payload.pop(key, None)

        response = await client.post(reset_password_url, json=base_payload)
        assert response.status_code == 422, f"Failed for case: {description}"

    async def test_reset_password_blocked_user(self, client: AsyncClient, session: AsyncSession,
                                               reset_password_url: str):
        """Test password reset for blocked/inactive user"""
        blocked_user = UserFactory.build(
            email="blocked@mail.com",
            phone_number="+1234567890",
            is_active=False  # or is_blocked=True depending on your model
        )
        session.add(blocked_user)
        await session.commit()
        await session.refresh(blocked_user)

        code = VerificationCodeFactory.build(
            routing_key=VerificationCodeRoutingKey.PASSWORD_RESET,
            destination=Destination.EMAIL,
            user_id=blocked_user.id
        )
        session.add(code)
        await session.commit()

        payload = self.create_payload(
            email=blocked_user.email,
            code=code.code
        )

        response = await client.post(reset_password_url, json=payload)

        assert response.status_code == 403  # Or whatever status check_user returns

    async def test_reset_password_expired_code(self, client: AsyncClient, session: AsyncSession,
                                               reset_password_url: str, test_user):
        """Test password reset with expired verification code"""
        # Create expired verification code
        expired_code = VerificationCodeFactory.build(
            routing_key=VerificationCodeRoutingKey.PASSWORD_RESET,
            destination=Destination.EMAIL,
            user_id=test_user.id,
            created_at=datetime.now(UTC) - timedelta(hours=25),  # Assuming 24h expiry
            expires_at=datetime.now(UTC) - timedelta(hours=1)
        )
        session.add(expired_code)
        await session.commit()

        payload = self.create_payload(
            email=test_user.email,
            code=expired_code.code
        )

        response = await client.post(reset_password_url, json=payload)

        assert response.status_code == 400
        assert 'Invalid code' in response.json()['detail']

    @pytest.mark.parametrize("weak_password,description", [
        ('123456', 'too simple'),
        ('password', 'no numbers or special chars'),
        ('Pass1!', 'too short'),
        ('passwordpassword1!', 'no uppercase'),
        ('PASSWORDPASSWORD1!', 'no lowercase'),
    ])
    async def test_reset_password_weak_password(self, client: AsyncClient,
                                                reset_password_url: str,
                                                test_user, verification_code,
                                                weak_password: str,
                                                description: str):
        """Test password reset with weak password that doesn't meet requirements"""
        payload = self.create_payload(
            email=test_user.email,
            code=verification_code.code,
            new_password1=weak_password
        )

        response = await client.post(reset_password_url, json=payload)
        assert response.status_code in [422,400], f"Failed for password: {description}"