import uuid
from datetime import datetime, UTC, timedelta
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import UserFactory, RefreshTokenFactory, UserSessionFactory


@pytest.mark.asyncio
class TestRefreshTokenEndpoint:
    """Tests for the /refresh endpoint"""

    async def test_refresh_token_success(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test successful token refresh with valid refresh token and access token"""
        # Create user
        user = UserFactory.build()
        session.add(user)
        await session.flush()

        # Create valid refresh token
        jti = str(uuid.uuid4())
        token_family = str(uuid.uuid4())
        refresh_token = RefreshTokenFactory.build(
            user_id=user.id,
            jti=jti,
            token_family=token_family,
            is_active=True,
            expires_at=datetime.now(UTC) + timedelta(days=7)
        )
        session.add(refresh_token)
        await session.flush()

        # Create an associated session
        user_session = UserSessionFactory.build(
            user_id=str(user.uuid_key),
            refresh_token_id=refresh_token.id,
            is_active=True
        )
        session.add(user_session)
        await session.commit()

        # Mock auth service methods
        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": jti,
            "type": "refresh",
            "sub": user.uuid_key,
            "token_family": token_family
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(return_value=False)
        mock_auth_service.get_payload_for_token = AsyncMock(side_effect=[
            {"jti": str(uuid.uuid4()), "type": "refresh", "token_family": token_family},
            {"jti": str(uuid.uuid4()), "type": "access"}
        ])
        mock_auth_service.generate_token = AsyncMock(side_effect=[
            "new_access_token",
            "new_refresh_token"
        ])
        mock_auth_service.blacklist_token = AsyncMock()

        payload = {
            "refresh_token": "valid_refresh_token",
            "access_token": "valid_access_token"
        }

        response = await client.post("v1/refresh", json=payload)
        print(response.json())

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["access_token"] == "new_access_token"
        assert data["refresh_token"] == "new_refresh_token"

    async def test_refresh_token_blacklisted(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test refresh with blacklisted token"""
        jti = str(uuid.uuid4())

        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": jti,
            "type": "refresh",
            "sub": str(uuid.uuid4()),
            "token_family": str(uuid.uuid4())
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(return_value=True)

        payload = {
            "refresh_token": "blacklisted_token",
            "access_token": "some_access_token"
        }

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 401
        assert "expired or revoked" in response.json()["detail"]

    async def test_refresh_token_invalid_type(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test refresh with wrong token type (e.g., access token instead of refresh)"""
        jti = str(uuid.uuid4())

        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": jti,
            "type": "access",  # Wrong type
            "sub": str(uuid.uuid4()),
            "token_family": str(uuid.uuid4())
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(return_value=False)

        payload = {
            "refresh_token": "access_token_instead",
            "access_token": "some_access_token"
        }

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 401
        assert "Invalid refresh token" in response.json()["detail"]

    async def test_refresh_token_user_not_found(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test refresh when user doesn't exist"""
        jti = str(uuid.uuid4())
        non_existent_uuid = str(uuid.uuid4())

        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": jti,
            "type": "refresh",
            "sub": non_existent_uuid,
            "token_family": str(uuid.uuid4())
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(return_value=False)

        payload = {
            "refresh_token": "token_for_deleted_user",
            "access_token": "some_access_token"
        }

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 401
        assert "User not found or inactive" in response.json()["detail"]

    async def test_refresh_token_user_inactive(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test refresh with inactive user account"""
        # Create inactive user
        user = UserFactory.build(is_active=False)
        session.add(user)
        await session.commit()

        jti = str(uuid.uuid4())

        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": jti,
            "type": "refresh",
            "sub": user.uuid_key,
            "token_family": str(uuid.uuid4())
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(return_value=False)

        payload = {
            "refresh_token": "token_for_inactive_user",
            "access_token": "some_access_token"
        }

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 401
        assert "User not found or inactive" in response.json()["detail"]

    async def test_refresh_token_reuse_detection(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test detection of refresh token reuse (replay attack)"""
        # Create user
        user = UserFactory.build()
        session.add(user)
        await session.flush()

        # Create token family with rotation history
        token_family = str(uuid.uuid4())
        old_jti = str(uuid.uuid4())
        current_jti = str(uuid.uuid4())

        # Old token (already used)
        old_token = RefreshTokenFactory.build(
            user_id=user.id,
            jti=old_jti,
            token_family=token_family,
            is_active=False,
            used_at=datetime.now(UTC) - timedelta(hours=1)
        )
        session.add(old_token)

        # Current active token
        current_token = RefreshTokenFactory.build(
            user_id=user.id,
            jti=current_jti,
            token_family=token_family,
            is_active=True,
            expires_at=datetime.now(UTC) + timedelta(days=7)
        )
        session.add(current_token)

        # Create session
        user_session = UserSessionFactory.build(
            user_id=str(user.uuid_key),
            refresh_token_id=old_token.id,
            is_active=True
        )
        session.add(user_session)
        await session.commit()

        # Try to use the old token (reuse attack)
        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": old_jti,  # Using old JTI
            "type": "refresh",
            "sub": user.uuid_key,
            "token_family": token_family
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(return_value=False)
        mock_auth_service.blacklist_token = AsyncMock()

        payload = {
            "refresh_token": "old_already_used_token",
            "access_token": "some_access_token"
        }

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 401
        assert "reuse detected" in response.json()["detail"].lower()

        # Verify that blacklist was called
        mock_auth_service.blacklist_token.assert_called_with('refresh', old_jti)

    async def test_refresh_token_expired(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test refresh with expired refresh token"""
        # Create user
        user = UserFactory.build()
        session.add(user)
        await session.flush()

        # Create expired refresh token
        jti = str(uuid.uuid4())
        token_family = str(uuid.uuid4())
        expired_token = RefreshTokenFactory.create_expired(
            user_id=user.id,
            jti=jti,
            token_family=token_family
        )
        session.add(expired_token)
        await session.commit()

        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": jti,
            "type": "refresh",
            "sub": user.uuid_key,
            "token_family": token_family
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(return_value=False)

        payload = {
            "refresh_token": "expired_refresh_token",
            "access_token": "some_access_token"
        }

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 401

    async def test_refresh_token_missing_jti(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test refresh with token payload missing JTI"""
        mock_auth_service.verify_token = AsyncMock(return_value={
            "type": "refresh",
            "sub": str(uuid.uuid4()),
            "token_family": str(uuid.uuid4())
            # Missing "jti" field
        })

        payload = {
            "refresh_token": "token_without_jti",
            "access_token": "some_access_token"
        }

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 401
        assert "expired or revoked" in response.json()["detail"]


    async def test_refresh_token_concurrent_requests(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):
        """Test handling of concurrent refresh requests with same token"""
        # Create user
        user = UserFactory.build()
        session.add(user)
        await session.flush()

        # Create refresh token
        jti = str(uuid.uuid4())
        token_family = str(uuid.uuid4())
        refresh_token = RefreshTokenFactory.build(
            user_id=user.id,
            jti=jti,
            token_family=token_family,
            is_active=True,
            expires_at=datetime.now(UTC) + timedelta(days=7)
        )
        session.add(refresh_token)
        await session.flush()

        # Create session
        user_session = UserSessionFactory.build(
            user_id=str(user.uuid_key),
            refresh_token_id=refresh_token.id,
            is_active=True
        )
        session.add(user_session)
        await session.commit()

        # First request succeeds
        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": jti,
            "type": "refresh",
            "sub": user.uuid_key,
            "token_family": token_family
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(side_effect=[False, True])
        mock_auth_service.get_payload_for_token = AsyncMock(side_effect=[
            {"jti": str(uuid.uuid4()), "type": "refresh", "token_family": token_family},
            {"jti": str(uuid.uuid4()), "type": "access"}
        ])
        mock_auth_service.generate_token = AsyncMock(side_effect=[
            "new_access_token",
            "new_refresh_token"
        ])
        mock_auth_service.blacklist_token = AsyncMock()

        payload = {
            "refresh_token": "concurrent_token",
            "access_token": "some_access_token"
        }

        # First request should succeed
        response1 = await client.post("v1/refresh", json=payload)
        assert response1.status_code == 200

        # Second request with same token should fail (blacklisted)
        response2 = await client.post("v1/refresh", json=payload)
        assert response2.status_code == 401

    async def test_refresh_token_invalid_payload(
            self,
            client: AsyncClient
    ):
        """Test refresh with invalid request payload"""
        # Missing refresh_token field
        response = await client.post("v1/refresh", json={"access_token": "some_token"})
        assert response.status_code == 422

        # Invalid type for refresh_token
        response = await client.post("v1/refresh", json={
            "refresh_token": 123,
        })
        assert response.status_code == 422

        # Invalid type for access_token
        response = await client.post("v1/refresh", json={
            "refresh_token": "some_token",
        })
        assert response.status_code == 401

        # Extra fields
        response = await client.post("v1/refresh", json={
            "refresh_token": "token",
            "access_token": "token",
            "extra_field": "should_not_be_here"
        })
        print(response.json())
        assert response.status_code == 401  # Depends on token validation

    async def test_refresh_token_session_update(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service
    ):

        user = UserFactory.build()
        session.add(user)
        await session.flush()

        jti = str(uuid.uuid4())
        token_family = str(uuid.uuid4())
        refresh_token = RefreshTokenFactory.build(
            user_id=user.id,
            jti=jti,
            token_family=token_family,
            is_active=True,
            expires_at=datetime.now(UTC) + timedelta(days=7)
        )
        session.add(refresh_token)
        await session.flush()

        old_activity = datetime.now(UTC) - timedelta(hours=2)
        user_session = UserSessionFactory.build(
            user_id=str(user.uuid_key),
            refresh_token_id=refresh_token.id,
            is_active=True,
            last_activity=old_activity
        )
        session.add(user_session)
        await session.commit()

        # Mock services
        mock_auth_service.verify_token = AsyncMock(return_value={
            "jti": jti,
            "type": "refresh",
            "sub": user.uuid_key,
            "token_family": token_family
        })
        mock_auth_service.is_token_blacklisted = AsyncMock(return_value=False)
        mock_auth_service.get_payload_for_token = AsyncMock(side_effect=[
            {"jti": str(uuid.uuid4()), "type": "refresh", "token_family": token_family},
            {"jti": str(uuid.uuid4()), "type": "access"}
        ])
        mock_auth_service.generate_token = AsyncMock(side_effect=[
            "new_access_token",
            "new_refresh_token"
        ])
        mock_auth_service.blacklist_token = AsyncMock()

        # Track session update call

        payload = {
            "refresh_token": "valid_refresh_token",
            "access_token": "current_access_token"
        }

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 200


    async def test_refresh_missing_refresh_token(
            self,
            client: AsyncClient
    ):
        """Test refresh with missing refresh_token"""
        payload = {"access_token": "some_access_token"}

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 422
        assert "refresh_token" in str(response.json())

    async def test_refresh_both_tokens_missing(
            self,
            client: AsyncClient
    ):
        """Test refresh with both tokens missing"""
        payload = {}

        response = await client.post("v1/refresh", json=payload)

        assert response.status_code == 422