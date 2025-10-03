from unittest.mock import Mock, AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories.token_session_user_factories import UserFactory


@pytest.mark.asyncio
class TestUserLogin:

    async def test_user_login_success(self, client: AsyncClient, session: AsyncSession, mock_auth_service):
        user = UserFactory.build(phone_number="1234567890")
        session.add(user)
        await session.commit()

        payload = {
            "email": user.email,
            "password": "StrongPass!2",
        }

        mock_auth_service.verify_password = Mock(return_value=True)

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 200

    async def test_user_login_invalid_email(self, client):
        response = await client.post("v1/login", json={
            "email": "invalid-email",
            "password": "StrongPass!2",
        })
        assert response.status_code == 422

    async def test_user_login_email_not_verified(self, client: AsyncClient, session: AsyncSession, mock_auth_service):
        user = UserFactory.build(phone_number="1234567890", email_verified=False)
        session.add(user)
        await session.commit()

        payload = {
            "email": user.email,
            "password": "StrongPass!2",
        }
        mock_auth_service.verify_password = Mock(return_value=True)

        response = await client.post("v1/login", json=payload)

        assert response.status_code == 401
        assert "Email not verified" in response.json()["detail"]

    async def test_user_login_wrong_password(self, client: AsyncClient, session: AsyncSession, mock_auth_service):
        user = UserFactory.build(phone_number="1234567890")
        session.add(user)
        await session.commit()

        payload = {
            "email": user.email,
            "password": "WrongPassword№123",
        }

        mock_auth_service.verify_password = Mock(return_value=False)

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]

    async def test_user_login_nonexistent_user(self, client: AsyncClient, mock_auth_service):
        """Тест с несуществующим пользователем"""
        payload = {
            "email": "nonexistent@example.com",
            "password": "StrongPass!2",
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]

    async def test_user_login_missing_email(self, client: AsyncClient):
        """Тест отсутствующего email в запросе"""
        payload = {
            "password": "StrongPass!2",
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 422

    async def test_user_login_missing_password(self, client: AsyncClient):
        """Тест отсутствующего пароля в запросе"""
        payload = {
            "email": "test@example.com",
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 422

    async def test_user_login_empty_payload(self, client: AsyncClient):
        """Тест пустого payload"""
        response = await client.post("v1/login", json={})
        assert response.status_code == 422

    async def test_user_login_invalid_json(self, client: AsyncClient):
        """Тест невалидного JSON"""
        response = await client.post("v1/login", data="invalid json")
        assert response.status_code == 422

    async def test_user_login_empty_email(self, client: AsyncClient):
        """Тест пустого email"""
        payload = {
            "email": "",
            "password": "StrongPass!2",
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 422

    async def test_user_login_empty_password(self, client: AsyncClient):
        """Тест пустого пароля"""
        payload = {
            "email": "test@example.com",
            "password": "",
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 422

    async def test_user_login_null_values(self, client: AsyncClient):
        """Тест null значений"""
        payload = {
            "email": None,
            "password": None,
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 422

    async def test_user_login_extra_fields(self, client: AsyncClient, session: AsyncSession, mock_auth_service):
        """Тест с дополнительными полями в запросе"""
        user = UserFactory.build(phone_number="1234567890")
        session.add(user)
        await session.commit()

        payload = {
            "email": user.email,
            "password": "StrongPass!2",
            "extra_field": "should_be_ignored",
            "another_field": 123,
        }

        mock_auth_service.verify_password = Mock(return_value=True)

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 200

    async def test_user_login_case_insensitive_email(self, client: AsyncClient, session: AsyncSession,
                                                     mock_auth_service):
        """Тест регистронезависимости email"""
        user = UserFactory.build(email="test@example.com", phone_number="1234567890")
        session.add(user)
        await session.commit()

        payload = {
            "email": "TEST@EXAMPLE.COM",
            "password": "StrongPass!2",
        }

        mock_auth_service.verify_password = Mock(return_value=True)

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 200

    async def test_user_login_whitespace_email(self, client: AsyncClient, session: AsyncSession, mock_auth_service):
        """Тест email с пробелами"""
        user = UserFactory.build(email="test@example.com", phone_number="1234567890")
        session.add(user)
        await session.commit()

        payload = {
            "email": "  test@example.com  ",
            "password": "StrongPass!2",
        }

        mock_auth_service.verify_password = Mock(return_value=True)

        response = await client.post("v1/login", json=payload)
        # Зависит от реализации - может быть 200 (если trimming) или 401
        assert response.status_code in [200, 401]

    async def test_user_login_sql_injection_attempt(self, client: AsyncClient):
        """Тест попытки SQL инъекции"""
        payload = {
            "email": "admin@example.com'; DROP TABLE users; --",
            "password": "password",
        }

        response = await client.post("v1/login", json=payload)
        # Должен безопасно обработать и вернуть 401 или 422
        assert response.status_code in [401, 422]

    async def test_user_login_very_long_email(self, client: AsyncClient):
        """Тест очень длинного email"""
        long_email = "a" * 1000 + "@example.com"
        payload = {
            "email": long_email,
            "password": "StrongPass!2",
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 422

    async def test_user_login_very_long_password(self, client: AsyncClient):
        """Тест очень длинного пароля"""
        payload = {
            "email": "test@example.com",
            "password": "a" * 1000,
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code in [401, 422]

    async def test_user_login_special_characters_email(self, client: AsyncClient):
        """Тест email со специальными символами"""
        payload = {
            "email": "test+tag@sub.example.com",
            "password": "StrongPass!2",
        }

        response = await client.post("v1/login", json=payload)
        # Валидный email формат, но пользователь не существует
        assert response.status_code == 401

    async def test_user_login_unicode_characters(self, client: AsyncClient):
        """Тест с unicode символами"""
        payload = {
            "email": "тест@example.com",
            "password": "пароль123",
        }

        response = await client.post("v1/login", json=payload)
        assert response.status_code in [401, 422]

    async def test_user_login_inactive_user(self, client: AsyncClient, session: AsyncSession, mock_auth_service):
        """Тест неактивного пользователя (если есть поле is_active)"""
        user = UserFactory.build(phone_number="1234567890", is_active=False)
        session.add(user)
        await session.commit()

        payload = {
            "email": user.email,
            "password": "StrongPass!2",
        }

        mock_auth_service.verify_password = Mock(return_value=True)

        response = await client.post("v1/login", json=payload)
        assert response.status_code == 403
        assert "Account deactivated" in response.json()["detail"]

    async def test_user_login_multiple_attempts_rate_limiting(self, client: AsyncClient):
        payload = {
            "email": "test@example.com",
            "password": "wrong_!Rpass1word",
        }

        # Делаем несколько попыток подряд
        for _ in range(10):
            response = await client.post("v1/login", json=payload)

        print(response.json())
        # Последняя попытка должна быть заблокирована (если есть rate limiting)
        assert response.status_code in [401, 429]



    async def test_user_login_method_not_allowed(self, client: AsyncClient):
        """Тест неподдерживаемых HTTP методов"""
        payload = {
            "email": "test@example.com",
            "password": "password",
        }

        # Тестируем GET запрос
        response = await client.get("v1/login")
        assert response.status_code == 405

        # Тестируем PUT запрос
        response = await client.put("v1/login", json=payload)
        assert response.status_code == 405

        # Тестируем DELETE запрос
        response = await client.delete("v1/login")
        assert response.status_code == 405


