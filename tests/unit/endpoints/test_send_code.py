import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from database.models import User
from tests.factories import UserFactory

@pytest.mark.asyncio
class TestSendCode:

    async def test_send_code_success(self, client: AsyncClient, session: AsyncSession, mock_auth_service):
        user = UserFactory.build(phone_number="1234567890", email_verified=False)
        session.add(user)
        await session.commit()


        response = await client.post("v1/send-code", json={
            "phone_number": "1234567890"
        })
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}