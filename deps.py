from typing import Any, AsyncGenerator

from fastapi_limiter.depends import RateLimiter
from sqlalchemy.ext.asyncio import AsyncSession

from auth.service import AuthService
import aioboto3
import redis
from aioboto3 import Session
from fastapi import Depends
from redis.asyncio import Redis

from config import settings
from database.crud.singin_key import SigningKeyService
from database.db.session import get_async_db
from rate_limit_ids import user_identifier


async def get_redis_client()-> AsyncGenerator[Redis, Any]:
    redis_client = await redis.asyncio.from_url(
        settings.REDIS_URL,
        decode_responses=True
    )
    yield redis_client

async def get_kms_session()-> AsyncGenerator[Session, Any]:
    kms_session = aioboto3.Session(
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    )
    yield kms_session

async def get_auth_service(redis_client: Redis = Depends(get_redis_client), kms_session: Session = Depends(get_kms_session),
                           db: AsyncSession = Depends(get_async_db)):
    sign_key_service = SigningKeyService(db)
    active_signing_key = await sign_key_service.get_newer_active_key()
    yield AuthService(kms_session, redis_client, str(active_signing_key.key_arn))


register_rate_limiter_dep = RateLimiter(times=15, seconds=120, identifier=user_identifier)
login_rate_limiter_dep = RateLimiter(times=10, seconds=60, identifier=user_identifier)