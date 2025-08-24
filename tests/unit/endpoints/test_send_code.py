import uuid
from datetime import datetime, UTC, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from database.models.verification_code import Destination, VerificationCode, VerificationCodeRoutingKey
from tests.factories.token_session_user_factories import UserFactory


@pytest.mark.asyncio
class TestSendCode:

    async def test_send_code_success_email(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        """Тест успешной отправки кода на email"""
        user = UserFactory.build(
            phone_number="1234567890",
            email="test@example.com",
            email_verified=False
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        response = await client.post(f"v1/verification-code/{user.uuid_key}/email/send-code")

        assert response.status_code == 200
        assert response.json() == {"message": "Code sent"}  # Исправлено на правильный ответ

        mock_rabbit_mq.publish.assert_called_once()
        call_args = mock_rabbit_mq.publish.call_args
        assert call_args[1]["routing_key"] == "auth.send_code"

        payload = call_args[1]["payload"]
        assert payload["user_uuid"] == user.uuid_key
        assert payload["destination"].value == "email"
        assert payload["first_name"] == user.first_name
        assert payload["last_name"] == user.last_name
        assert payload["email"] == user.email
        assert payload["phone_number"] == user.phone_number
        assert "code" in payload
        assert "expire_minutes" in payload

    async def test_send_code_sms_where_phone_number_exists_but_not_verified(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        user = UserFactory.build(
            phone_number="1234567890",
            email="test@example.com",
            phone_verified=False
        )
        user_with_same_unverified_phone = UserFactory.build(
            phone_number="1234567890",
            phone_verified=False
        )
        session.add(user)
        session.add(user_with_same_unverified_phone)
        await session.commit()
        await session.refresh(user)
        await session.refresh(user_with_same_unverified_phone)

        response = await client.post(f"v1/verification-code/{user_with_same_unverified_phone.uuid_key}/sms/send-code")
        print(response.json())
        assert response.status_code == 200
        assert response.json() == {"message": "Code sent"}
        mock_rabbit_mq.publish.assert_called_once()



    async def test_send_code_success_sms(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        """Тест успешной отправки кода по SMS"""
        user = UserFactory.build(
            phone_number="1234567890",
            email="test@example.com",
            phone_verified=False
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        response = await client.post(f"v1/verification-code/{user.uuid_key}/sms/send-code")
        print(response.json())

        assert response.status_code == 200
        assert response.json() == {"message": "Code sent"}
        mock_rabbit_mq.publish.assert_called_once()

    async def test_send_code_user_not_found(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        """Тест с несуществующим пользователем"""
        fake_uuid = "non-existent-uuid-123"

        response = await client.post(f"v1/verification-code/{fake_uuid}/email/send-code")

        assert response.status_code == 404
        mock_rabbit_mq.publish.assert_not_called()

    async def test_send_code_rate_limit_exceeded(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        """Тест превышения лимита отправки кодов"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com", email_verified=False)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем недавно отправленный код, чтобы симулировать rate limit
        recent_code = VerificationCode(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL,
            routing_key=VerificationCodeRoutingKey.ACCOUNT_VERIFICATION,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            is_verified=True,
            uuid_key=str(uuid.uuid4())
        )
        session.add(recent_code)
        await session.commit()

        response = await client.post(f"v1/verification-code/{user.uuid_key}/email/send-code")
        print(response.json())

        assert response.status_code == 429
        response_data = response.json()
        assert "Wait before send new code" in response_data.get("detail", "")
        mock_rabbit_mq.publish.assert_not_called()

    async def test_send_code_invalid_destination(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        """Тест с неверным типом destination"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        response = await client.post(f"v1/verification-code/{user.uuid_key}/invalid_destination/send-code")

        assert response.status_code == 422  # Validation error
        mock_rabbit_mq.publish.assert_not_called()

    async def test_send_code_malformed_uuid(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        """Тест с некорректным форматом UUID"""
        response = await client.post("v1/verification-code/invalid-uuid-format/email/send-code")

        assert response.status_code == 404
        mock_rabbit_mq.publish.assert_not_called()


    async def test_send_code_multiple_rapid_requests(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        """Тест множественных быстрых запросов для проверки rate limiter"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com", email_verified=False)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Отправляем несколько запросов подряд
        responses = []
        for i in range(5):
            response = await client.post(f"v1/verification-code/{user.uuid_key}/email/send-code")
            responses.append(response)

        # Первый запрос должен быть успешным
        assert responses[0].status_code == 200

        # Последующие запросы должны блокироваться rate limiter или business logic
        blocked_responses = [r for r in responses[1:] if r.status_code in [400, 429]]
        assert len(blocked_responses) > 0

    async def test_send_code_payload_structure(self, client: AsyncClient, session: AsyncSession, mock_rabbit_mq):
        """Детальный тест структуры payload для RabbitMQ"""
        user = UserFactory.build(
            phone_number="+1234567890",
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            email_verified=False
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        response = await client.post(f"v1/verification-code/{user.uuid_key}/email/send-code")

        assert response.status_code == 200
        mock_rabbit_mq.publish.assert_called_once()

        call_args = mock_rabbit_mq.publish.call_args
        payload = call_args[1]["payload"]

        # Проверяем все обязательные поля
        required_fields = [
            "user_uuid", "code", "destination", "first_name",
            "last_name", "email", "expire_minutes", "phone_number"
        ]
        for field in required_fields:
            assert field in payload, f"Field {field} is missing in payload"

        # Проверяем типы данных
        assert isinstance(payload["user_uuid"], str)
        assert isinstance(payload["code"], str)
        assert isinstance(payload["destination"].value, str)
        assert isinstance(payload["expire_minutes"], int)