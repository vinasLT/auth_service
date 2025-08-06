import asyncio
import uuid
from datetime import datetime, UTC, timedelta
from typing import Generator, AsyncGenerator, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from httpx import AsyncClient
from sqlalchemy import StaticPool, event
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from auth.service import AuthService
from database.db.session import get_async_db
from database.models import Base, RefreshToken, Role, User
from deps import register_rate_limiter_dep, login_rate_limiter_dep, get_auth_service
from main import app
from httpx import ASGITransport

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="session")
def event_loop() -> Generator:
    """Создание event loop для всей сессии тестов"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(autouse=True)
async def mock_fastapi_limiter():
    with patch("fastapi_limiter.FastAPILimiter.init", AsyncMock(return_value=None)):
        with patch.object(FastAPILimiter, "redis", AsyncMock(return_value=True)):
            yield

@pytest_asyncio.fixture(scope="session")
async def async_engine():
    """Provide an async SQLAlchemy engine for tests."""
    engine = create_async_engine(TEST_DB_URL, echo=True)
    # Create all tables defined in your SQLAlchemy models
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def get_app():
    return app
@pytest_asyncio.fixture
async def client(async_db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:

    async def override_get_db():
        yield async_db_session

    async def mock_rate_limiter():
        pass

    app.dependency_overrides[register_rate_limiter_dep] = mock_rate_limiter
    app.dependency_overrides[login_rate_limiter_dep] = mock_rate_limiter

    app.dependency_overrides[get_async_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()

@pytest_asyncio.fixture(scope="function")
async def async_db_session(async_engine) -> AsyncGenerator[AsyncSession, Any]:
    async with async_engine.connect() as conn:
        trans = await conn.begin()
        async_session_factory = async_sessionmaker(bind=conn, expire_on_commit=False, class_=AsyncSession)
        async with async_session_factory() as session:
            await session.begin_nested()

            @event.listens_for(session.sync_session, "after_transaction_end")
            def _restart_savepoint(sess, trans_):
                if trans_.nested and not trans_._parent.nested:
                    sess.begin_nested()

            yield session
        await trans.rollback()


@pytest_asyncio.fixture
def mock_auth_service():
    """Мок для AuthService"""
    service = AsyncMock(spec=AuthService)

    # Настройка дефолтных возвращаемых значений
    service.hash_password.return_value = "hashed_password"
    service.verify_password.return_value = True
    service.generate_token.return_value = "test_token"
    service.verify_token.return_value = {
        "sub": str(uuid.uuid4()),
        "email": "test@example.com",
        "type": "access",
        "jti": str(uuid.uuid4()),
        "token_family": str(uuid.uuid4()),
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    }
    service.get_payload_for_token.return_value = {
        "sub": str(uuid.uuid4()),
        "email": "test@example.com",
        "type": "access",
        "jti": str(uuid.uuid4()),
        "token_family": str(uuid.uuid4()),
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    }
    service.is_token_blacklisted.return_value = False
    service.blacklist_token.return_value = None
    service.access_token_ttl = 3600  # 1 hour
    service.refresh_token_ttl = 604800  # 7 days

    return service


def mock_auth_service_function():
    """Мок для AuthService"""
    service = AsyncMock(spec=AuthService)

    # Настройка дефолтных возвращаемых значений
    service.hash_password.return_value = "hashed_password"
    service.verify_password.return_value = True
    service.generate_token.return_value = "test_token"
    service.verify_token.return_value = {
        "sub": str(uuid.uuid4()),
        "email": "test@example.com",
        "type": "access",
        "jti": str(uuid.uuid4()),
        "token_family": str(uuid.uuid4()),
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    }
    service.get_payload_for_token.return_value = {
        "sub": str(uuid.uuid4()),
        "email": "test@example.com",
        "type": "access",
        "jti": str(uuid.uuid4()),
        "token_family": str(uuid.uuid4()),
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    }
    service.is_token_blacklisted.return_value = False
    service.blacklist_token.return_value = None
    service.access_token_ttl = 3600  # 1 hour
    service.refresh_token_ttl = 604800  # 7 days

    return service

@pytest_asyncio.fixture
def mock_redis():
    redis_mock = AsyncMock()
    redis_mock.get.return_value = None
    redis_mock.setex.return_value = True
    redis_mock.exists.return_value = False
    return redis_mock


@pytest.fixture
def sample_user_data():
    """Фикстура с тестовыми данными пользователя"""
    return {
        "email": "test@example.com",
        "phone_number": "+1234567890",
        "password": "TestPassword123!",
        "username": "testuser"
    }


@pytest.fixture
def sample_token_payload():
    """Фикстура с тестовым payload токена"""
    user_uuid = str(uuid.uuid4())
    return {
        "sub": user_uuid,
        "email": "test@example.com",
        "type": "access",
        "jti": str(uuid.uuid4()),
        "roles": ["user"],
        "permissions": ["read"],
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(UTC).timestamp())
    }


@pytest_asyncio.fixture
async def create_test_user(async_db_session: AsyncSession):
    """Фикстура для создания тестового пользователя в БД"""

    async def _create_user(
            email: str = "test@example.com",
            password_hash: str = "hashed_password!1I",
            is_active: bool = True,
            phone_number: str = "+1234567890"
    ) -> User:
        user = User(
            uuid_key=str(uuid.uuid4()),
            email=email,
            username=email.split('@')[0],
            password_hash=password_hash,
            phone_number=phone_number,
            is_active=is_active,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        async_db_session.add(user)
        await async_db_session.commit()
        await async_db_session.refresh(user)
        return user

    return _create_user


@pytest_asyncio.fixture
async def create_test_role(async_db_session: AsyncSession):
    """Фикстура для создания тестовой роли"""

    async def _create_role(
            name: str = "user",
            is_default: bool = True
    ) -> Role:
        role = Role(
            name=name,
            description=f"{name} role",
            is_default=is_default,
            created_at=datetime.now(UTC),
        )
        async_db_session.add(role)
        await async_db_session.commit()
        await async_db_session.refresh(role)
        return role

    return _create_role


@pytest_asyncio.fixture
async def create_refresh_token(async_db_session: AsyncSession):
    """Фикстура для создания refresh токена"""

    async def _create_token(
            user_id: int,
            jti: str = None,
            token_family: str = None,
            is_active: bool = True
    ) -> RefreshToken:
        if not jti:
            jti = str(uuid.uuid4())
        if not token_family:
            token_family = str(uuid.uuid4())

        token = RefreshToken(
            jti=jti,
            user_id=user_id,
            token_family=token_family,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=7),
            device_name="Test Device",
            user_agent="Test User Agent",
            ip_address="127.0.0.1",
            is_active=is_active
        )
        async_db_session.add(token)
        await async_db_session.commit()
        await async_db_session.refresh(token)
        return token

    return _create_token


@pytest_asyncio.fixture
async def authenticated_client(
        client: AsyncClient,
        create_test_user,
        mock_auth_service
) -> AsyncGenerator[AsyncClient, Any]:
    """Фикстура для создания аутентифицированного клиента"""
    user = await create_test_user()

    # Создаем токен для пользователя
    access_token = "test_access_token"

    # Добавляем заголовок авторизации
    client.headers["Authorization"] = f"Bearer {access_token}"

    # Настраиваем мок для проверки токена
    with patch("security.get_current_user", return_value={
        "sub": user.uuid_key,
        "email": user.email,
        "jti": str(uuid.uuid4()),
        "type": "access"
    }):
        yield client


@pytest_asyncio.fixture
def mock_logger():
    """Мок для логгера"""
    logger = MagicMock()
    logger.info = MagicMock()
    logger.debug = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.critical = MagicMock()
    return logger


# Маркеры для различных типов тестов
pytest.mark.unit = pytest.mark.mark(name="unit")
pytest.mark.integration = pytest.mark.mark(name="integration")
pytest.mark.slow = pytest.mark.mark(name="slow")
pytest.mark.auth = pytest.mark.mark(name="auth")