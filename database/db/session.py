from typing import Any, AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, AsyncSession, async_sessionmaker
from config import settings

if settings.DEBUG:
    SQLALCHEMY_ASYNC_DATABASE_URL = "sqlite+aiosqlite:///./db.sqlite"
else:
    SQLALCHEMY_ASYNC_DATABASE_URL = settings.DATABASE_URL


engine_async: AsyncEngine = create_async_engine(SQLALCHEMY_ASYNC_DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(
    bind=engine_async,
    expire_on_commit=False,
    class_=AsyncSession,
)

async def get_async_db()-> AsyncGenerator[AsyncSession | Any, Any]:
    async with AsyncSessionLocal() as session:
        yield session

