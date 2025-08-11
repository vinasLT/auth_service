import pytest
from datetime import datetime, timezone, UTC, timedelta

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from security import get_current_user

@pytest.mark.asyncio
class TestVerify:

    async def test_verify_success(self, client: AsyncClient, session: AsyncSession, get_app):
        try:
            mock_current_user_data = {
                "sub": str(uuid.uuid4()),
                "jti": "mock-access-jti",
                "email": 'test@email.com',
                "roles": ['user'],
                'permissions': ['read:user', 'write:user'],
                "exp": datetime.now(timezone.utc).timestamp(),
                "type": "access"
            }
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
        get_app.dependency_overrides.clear()
        response = await client.get("/v1/verify")
        print(response.json())
        print(response.status_code)
        assert response.status_code == 403

