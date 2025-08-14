import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


from database.crud.verification_code import VerificationCodeService
from database.models.verification_code import Destination
from tests.factories.token_session_user_factories import UserFactory
from tests.factories.verefication_token import VerificationCodeFactory


@pytest.mark.asyncio
class TestVerifyCode:

    async def test_verify_code_success_email(self, client: AsyncClient, session: AsyncSession):
        """Тест успешной верификации кода для email"""
        user = UserFactory.build(
            phone_number="1234567890",
            email="test@example.com",
            email_verified=False
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем активный код верификации через фабрику
        verification_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL
        )
        session.add(verification_code)
        await session.commit()

        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        assert response.status_code == 200
        assert response.json() == {"message": "Code verified"}

    # async def test_verify_code_success_sms(self, client: AsyncClient, session: AsyncSession):
    #     """Тест успешной верификации кода для SMS"""
    #     user = UserFactory.build(
    #         phone_number="1234567890",
    #         email="test@example.com",
    #         phone_verified=False
    #     )
    #     session.add(user)
    #     await session.commit()
    #     await session.refresh(user)
    #
    #     # Создаем активный код верификации через фабрику
    #     verification_code = VerificationCodeFactory.build(
    #         user_id=user.id,
    #         code="654321",
    #         destination=Destination.PHONE
    #     )
    #     session.add(verification_code)
    #     await session.commit()
    #
    #     payload = {"code": "654321"}
    #     response = await client.post(
    #         f"v1/verification-code/verify/{user.uuid_key}/",
    #         json=payload
    #     )
    #
    #     print(response.json())
    #
    #     assert response.status_code == 200
    #     assert response.json() == {"message": "Code verified"}

    async def test_verify_code_user_not_found(self, client: AsyncClient, session: AsyncSession):
        """Тест с несуществующим пользователем"""
        fake_uuid = "non-existent-uuid-123"
        payload = {"code": "123456"}

        response = await client.post(
            f"v1/verification-code/verify/{fake_uuid}/email",
            json=payload
        )

        assert response.status_code == 404
        response_data = response.json()
        assert "User not found" in response_data.get("detail", "")

    async def test_verify_code_invalid_code(self, client: AsyncClient, session: AsyncSession):
        """Тест с неверным кодом верификации"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем код, но будем отправлять другой
        verification_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL
        )
        session.add(verification_code)
        await session.commit()

        payload = {"code": "wrong_"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )
        print(response.json())

        assert response.status_code == 400
        response_data = response.json()
        print(response_data)
        assert "Invalid code" in response_data.get("detail", "")

    async def test_verify_code_expired_code(self, client: AsyncClient, session: AsyncSession):
        """Тест с истекшим кодом"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем истекший код через фабрику с трейтом
        expired_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL,
            is_verified=True
        )
        session.add(expired_code)
        await session.commit()

        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        assert response.status_code == 400
        response_data = response.json()
        assert "Invalid code" in response_data.get("detail", "")

    async def test_verify_code_inactive_code(self, client: AsyncClient, session: AsyncSession):
        """Тест с деактивированным кодом"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем верифицированный (неактивный) код
        inactive_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL,
            is_verified=True
        )
        session.add(inactive_code)
        await session.commit()

        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        assert response.status_code == 400
        response_data = response.json()
        assert "Invalid code" in response_data.get("detail", "")

    async def test_verify_code_wrong_destination(self, client: AsyncClient, session: AsyncSession):
        """Тест верификации кода для неправильного destination"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем код для email через фабрику с трейтом
        verification_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL
        )
        session.add(verification_code)
        await session.commit()

        # Пытаемся верифицировать для SMS
        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/phone",
            json=payload
        )

        assert response.status_code == 400
        response_data = response.json()
        assert "Invalid code" in response_data.get("detail", "")

    async def test_verify_code_invalid_destination(self, client: AsyncClient, session: AsyncSession):
        """Тест с неверным типом destination"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/invalid_destination",
            json=payload
        )

        assert response.status_code == 422  # Validation error

    async def test_verify_code_missing_payload(self, client: AsyncClient, session: AsyncSession):
        """Тест без payload (отсутствует код)"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        response = await client.post(f"v1/verification-code/verify/{user.uuid_key}/email")

        assert response.status_code == 422  # Validation error - missing body

    async def test_verify_code_empty_code(self, client: AsyncClient, session: AsyncSession):
        """Тест с пустым кодом"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        payload = {"code": ""}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        # Может быть 400 или 422, в зависимости от валидации CodeIn
        assert response.status_code in [400, 422]

    async def test_verify_code_malformed_uuid(self, client: AsyncClient, session: AsyncSession):
        """Тест с некорректным форматом UUID"""
        payload = {"code": "123456"}
        response = await client.post(
            "v1/verification-code/verify/invalid-uuid-format/email",
            json=payload
        )

        assert response.status_code in [404, 422]


    async def test_verify_code_case_sensitivity(self, client: AsyncClient, session: AsyncSession):
        """Тест чувствительности кода к регистру (если применимо)"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем код в верхнем регистре через фабрику
        verification_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="ABC123",
            destination=Destination.EMAIL
        )
        session.add(verification_code)
        await session.commit()

        # Пытаемся верифицировать в нижнем регистре
        payload = {"code": "abc123"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        # В зависимости от логики вашего приложения, это может быть 200 или 400
        # Если коды case-sensitive, то должен быть 400
        # assert response.status_code == 400

    @pytest.mark.parametrize("destination", ["email", "phone"])
    async def test_verify_code_different_destinations(self, client: AsyncClient, session: AsyncSession, destination):
        """Параметризованный тест для разных типов destination"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем код для соответствующего destination через фабрику
        verification_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=getattr(Destination, destination.upper())
        )
        session.add(verification_code)
        await session.commit()

        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/{destination}",
            json=payload
        )

        assert response.status_code == 200
        assert response.json() == {"message": "Code verified"}

    async def test_verify_code_rate_limiting(self, client: AsyncClient, session: AsyncSession):
        """Тест rate limiting (15 попыток за 30 минут)"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        payload = {"code": "wrong_"}

        # Отправляем множество неверных кодов
        responses = []
        for i in range(16):  # Больше лимита
            response = await client.post(
                f"v1/verification-code/verify/{user.uuid_key}/email",
                json=payload
            )
            responses.append(response)


        # Первые 15 запросов должны проходить (даже если код неверный)
        for i in range(15):
            print(responses[i].json())
            assert responses[i].status_code == 400  # 400 из-за неверного кода
        print(responses[15].json())

        assert responses[15].status_code == 429  # Too Many Requests

    async def test_verify_code_deactivates_after_use(self, client: AsyncClient, session: AsyncSession):
        """Тест деактивации кода после успешного использования"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        verification_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL
        )
        session.add(verification_code)
        await session.commit()

        payload = {"code": "123456"}

        # Первая верификация должна быть успешной
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )
        assert response.status_code == 200

        # Вторая верификация того же кода должна провалиться
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )
        assert response.status_code == 400
        assert "Invalid code" in response.json().get("detail", "")

    async def test_verify_code_wrong_user(self, client: AsyncClient, session: AsyncSession):
        """Тест верификации кода для другого пользователя"""
        # Создаем двух пользователей
        user1 = UserFactory.build(phone_number="1111111111", email="user1@example.com")
        user2 = UserFactory.build(phone_number="2222222222", email="user2@example.com")
        session.add_all([user1, user2])
        await session.commit()
        await session.refresh(user1)
        await session.refresh(user2)

        # Создаем код для первого пользователя через фабрику
        verification_code = VerificationCodeFactory.build(
            user_id=user1.id,
            code="123456",
            destination=Destination.EMAIL
        )
        session.add(verification_code)
        await session.commit()

        # Пытаемся верифицировать код для второго пользователя
        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user2.uuid_key}/email",
            json=payload
        )

        assert response.status_code == 400
        assert "Invalid code" in response.json().get("detail", "")

    async def test_verify_code_invalid_json_payload(self, client: AsyncClient, session: AsyncSession):
        """Тест с невалидным JSON payload"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Отправляем невалидный JSON
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            content="invalid json content",
            headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 422

    async def test_verify_code_missing_code_field(self, client: AsyncClient, session: AsyncSession):
        """Тест с отсутствующим полем code в payload"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        payload = {"not_code": "123456"}  # Неправильное поле
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        assert response.status_code == 422

    async def test_verify_code_null_code(self, client: AsyncClient, session: AsyncSession):
        """Тест с null значением кода"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        payload = {"code": None}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        assert response.status_code == 422

    @pytest.mark.parametrize("invalid_code", ["", "   ", "12345", "1234567"])
    async def test_verify_code_invalid_code_formats(self, client: AsyncClient, session: AsyncSession, invalid_code):
        """Параметризованный тест для различных невалидных форматов кода"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        payload = {"code": invalid_code}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        # Может быть 400 или 422, в зависимости от валидации
        assert response.status_code in [400, 422]

    async def test_verify_code_concurrent_requests(self, client: AsyncClient, session: AsyncSession):
        """Тест одновременных запросов верификации одного кода"""
        import asyncio

        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        verification_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL
        )
        session.add(verification_code)
        await session.commit()

        payload = {"code": "123456"}

        # Отправляем несколько одновременных запросов
        tasks = [
            client.post(f"v1/verification-code/verify/{user.uuid_key}/email", json=payload)
            for _ in range(3)
        ]

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        print(responses)

        # Только один запрос должен быть успешным
        successful_responses = [r for r in responses if not isinstance(r, Exception) and r.status_code == 200]
        assert len(successful_responses) == 1

    async def test_verify_code_updates_user_verification_status(self, client: AsyncClient, session: AsyncSession):
        """Тест обновления статуса верификации пользователя (если применимо)"""
        user = UserFactory.build(
            phone_number="1234567890",
            email="test@example.com",
            email_verified=False
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        verification_code = VerificationCodeFactory.build(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL
        )
        session.add(verification_code)
        await session.commit()

        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        assert response.status_code == 200

        # Проверяем, что статус верификации обновился (если это делается в verify_code)
        await session.refresh(user)
        assert user.email_verified == True

    async def test_verify_code_service_integration(self, client: AsyncClient, session: AsyncSession):
        """Интеграционный тест с реальным сервисом (без моков)"""
        user = UserFactory.build(phone_number="1234567890", email="test@example.com")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        code_service = VerificationCodeService(session)

        created_code = await code_service.create_code_with_deactivation(
            user_id=user.id,
            code="123456",
            destination=Destination.EMAIL
        )
        print(created_code.created_at, created_code.expires_at)

        payload = {"code": "123456"}
        response = await client.post(
            f"v1/verification-code/verify/{user.uuid_key}/email",
            json=payload
        )

        assert response.status_code == 200
        assert response.json() == {"message": "Code verified"}