from typing import AsyncGenerator, Any

import pytest_asyncio
from fastapi_limiter import FastAPILimiter
from httpx import AsyncClient, ASGITransport
from redis import Redis
from sqlalchemy import event, StaticPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from auth.service import AuthService
from database.db.session import get_async_db
from database.models import Base
from deps import get_redis_client, get_auth_service
from main import app
from security import get_current_user
from tests.moks import get_test_redis_client, mock_auth_service, mock_get_current_user


@pytest_asyncio.fixture
async def get_app(mock_auth_service, mock_get_current_user, session):
    await FastAPILimiter.init(await get_test_redis_client())

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield session

    async def override_get_redis() -> Redis:
        return await get_test_redis_client()

    async def override_get_auth_service() -> AsyncGenerator[AuthService, Any]:
        yield mock_auth_service

    async def override_get_current_user() -> AsyncGenerator[AsyncSession, None]:
        yield mock_get_current_user

    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_async_db]     = override_get_db
    app.dependency_overrides[get_redis_client] = override_get_redis
    app.dependency_overrides[get_auth_service] = override_get_auth_service

    yield app

    # после всех тестов очищаем
    await FastAPILimiter.close()
    app.dependency_overrides.clear()

@pytest_asyncio.fixture
async def client(get_app):
    async with AsyncClient(transport=ASGITransport(get_app), base_url="http://test") as ac:
        yield ac

@pytest_asyncio.fixture
async def db():
    async with engine_test_async.connect() as conn:
        trans = await conn.begin()
        session = AsyncTestSessionLocal(bind=conn)

        await session.begin_nested()

        @event.listens_for(session.sync_session, "after_transaction_end")
        def restart_savepoint(sess, trans_):
            if trans_.nested and not trans_._parent.nested:
                sess.begin_nested()

        yield session

        await session.close()
        await trans.rollback()


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

engine_test_async = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False,
)

AsyncTestSessionLocal = async_sessionmaker(
    bind=engine_test_async,
    expire_on_commit=False,
    class_=AsyncSession,
)

@pytest_asyncio.fixture
async def session():
    async with engine_test_async.connect() as conn:
        trans = await conn.begin()
        session = AsyncSession(bind=conn, expire_on_commit=False)
        yield session
        await session.close()
        await trans.rollback()

@pytest_asyncio.fixture(scope="session", autouse=True)
async def init_db():
    async with engine_test_async.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine_test_async.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)













