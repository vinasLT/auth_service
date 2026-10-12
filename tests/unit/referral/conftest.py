import itertools
from typing import Callable, Optional

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from config import Permissions
from database.models import User, Referral
from dependencies.security import JWTUser, get_current_user
from tests.factories.token_session_user_factories import UserFactory

_phone_counter = itertools.count(5_000_000_000)


async def create_user(session: AsyncSession, **kwargs) -> User:
    kwargs.setdefault("phone_number", str(next(_phone_counter)))
    user = UserFactory.build(**kwargs)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def create_referred_user(session: AsyncSession, referrer: User, **kwargs) -> User:
    user = await create_user(session, referred_by_id=referrer.id, **kwargs)
    session.add(Referral(referrer_id=referrer.id, referred_user_id=user.id))
    await session.commit()
    return user


@pytest.fixture
def login_as(get_app) -> Callable[..., JWTUser]:
    def _login(user: User, permissions: Optional[list[Permissions]] = None) -> JWTUser:
        jwt_user = JWTUser(
            id=user.uuid_key,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            permissions=[p.value for p in permissions or []],
            token_jti="test-jti",
        )
        get_app.dependency_overrides[get_current_user] = lambda: jwt_user
        return jwt_user

    return _login
