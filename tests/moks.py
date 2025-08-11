import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict
from unittest.mock import Mock, AsyncMock

import fakeredis
import pytest
from sqlalchemy import StaticPool
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, async_sessionmaker, AsyncSession

from auth.service import AuthService
from deps import get_auth_service, get_rabbit_mq_service
from rabbit_service.service import RabbitMQPublisher


@pytest.fixture(scope='function')
def mock_auth_service():
    """Создаем мок AuthService"""
    mock_service = Mock(spec=get_auth_service)

    mock_service.verify_token = AsyncMock(return_value={
        "sub": "test-user-uuid",
        "email": "test@example.com",
        "type": "access",
        "roles": ["user"]
    })

    mock_service.refresh_token_ttl = 3600

    mock_service.get_payload_for_token = AsyncMock(side_effect=mock_get_payload_for_token)

    mock_service.generate_token = AsyncMock(return_value="mock-jwt-token")
    mock_service.is_token_blacklisted = AsyncMock(return_value=False)
    mock_service.blacklist_token = AsyncMock()
    mock_service.hash_password = Mock(return_value="hashed_password")
    mock_service.verify_password = Mock(return_value=True)

    return mock_service

@pytest.fixture(scope="function")
def mock_rabbit_mq():
    mock = Mock(spec=RabbitMQPublisher)
    mock.publish = AsyncMock(return_value=None)
    mock.connect = AsyncMock(return_value=None)
    mock.close = AsyncMock(return_value=None)
    return mock


async def mock_get_payload_for_token(token_type, user_uuid, email, roles_permissions=None, token_family=None):
    base_payload = {
        "iss": "test-issuer",
        "aud": "test-audience",
        "sub": user_uuid,
        "email": email,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=3600 if token_type == "access" else 86400),
        "jti": str(uuid.uuid4()),
        "type": token_type,
    }

    if token_type == "refresh":
        base_payload["token_family"] = token_family or str(uuid.uuid4())
    elif token_type == "access" and roles_permissions:
        base_payload.update(roles_permissions)

    return base_payload

@pytest.fixture
def mock_get_current_user():
    mock = AsyncMock(return_value={
        "sub": "test-user-uuid",
        "jti": "mock-access-jti",
        "email": "test@example.com"
    })
    return mock


async def get_test_redis_client():
    return fakeredis.aioredis.FakeRedis()

def get_test_rate_limiter():
    return None