import pytest
from datetime import datetime, timezone

import uuid

from asyncpg.pgproto.pgproto import timedelta
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from dependencies.security import get_current_user, JWTUser
from tests.factories.token_session_user_factories import UserFactory


@pytest.mark.asyncio
class TestVerify:

    async def test_verify_success(self, client: AsyncClient, session: AsyncSession, get_app):
        user = UserFactory.build(uuid_key="test-key")
        session.add(user)
        await session.commit()
        try:
            mock_current_user_data = JWTUser(id='test-key', token_jti='fwejfhwe', email='test@mail.com', first_name='test', last_name='test',
                    token_expires=datetime.now(timezone.utc)+ timedelta(days=1))

            get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

            headers = {
                'X-Forwarded-Method': 'GET',
                'X-Forwarded-Host': 'some.host',
                'X-Forwarded-Uri': 'some/uri'
            }

            response = await client.get("/v1/verify", headers=headers)
            print(response.headers)
            assert response.status_code == 200
            assert response.json() == {"status": "authorized"}
        finally:
            get_app.dependency_overrides.clear()


    async def test_verify_fail(self, client: AsyncClient, session: AsyncSession, get_app):
        override_current_user = get_app.dependency_overrides.pop(get_current_user, None)
        try:
            response = await client.get("/v1/verify")
            print(response.json())
            print(response.status_code)
            assert response.status_code == 401
        finally:
            if override_current_user:
                get_app.dependency_overrides[get_current_user] = override_current_user
