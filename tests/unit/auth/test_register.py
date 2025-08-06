# tests/unit/auth/test_register.py
"""Тесты для эндпоинта регистрации пользователей"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, AsyncMock

from deps import get_auth_service


@pytest.mark.asyncio
@pytest.mark.auth
class TestRegisterEndpoint:
    """Тесты для POST /register"""

    async def test_register_success(
            self,
            client: AsyncClient,
            create_test_role,
            mock_auth_service
    ):

        with patch("deps.get_auth_service", AsyncMock(return_value=mock_auth_service)):
            registration_data = {
                "email": "newuser@example.com",
                "phone_number": "+1234567890",
                "password": "SecurePassword123!",
            }

            # Выполнение
            response = await client.post(
                "v1/register",
                json=registration_data
            )

            # Проверка
            assert response.status_code == 200
            data = response.json()
            assert data["email"] == registration_data["email"]
            assert data["phone_number"] == registration_data["phone_number"]
            assert "id" in data
            assert "uuid_key" in data
            assert "password" not in data
            assert "password_hash" not in data

    async def test_register_email_already_exists(
            self,
            client: AsyncClient,
            async_db_session: AsyncSession,
            create_test_user,
            create_test_role
    ):
        """Тест регистрации с уже существующим email"""
        # Подготовка - создаем существующего пользователя
        existing_user = await create_test_user(email="existing@example.com")

        registration_data = {
            "email": "existing@example.com",
            "phone_number": "+9876543210",
            "password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }

        # Выполнение
        response = await client.post(
            "v1/register",
            json=registration_data
        )

        # Проверка
        assert response.status_code == 409  # Conflict
        data = response.json()
        assert "detail" in data
        assert "already registered" in data["detail"].lower()

    async def test_register_invalid_email_format(
            self,
            client: AsyncClient
    ):
        """Тест регистрации с невалидным форматом email"""
        registration_data = {
            "email": "invalid-email-format",
            "phone_number": "+1234567890",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!"
        }

        # Выполнение
        response = await client.post(
            "v1/register",
            json=registration_data
        )

        # Проверка
        assert response.status_code == 422  # Unprocessable Entity
        data = response.json()
        assert "errors" in data

    async def test_register_weak_password(
            self,
            client: AsyncClient
    ):
        """Тест регистрации со слабым паролем"""
        registration_data = {
            "email": "test@example.com",
            "phone_number": "+1234567890",
            "password": "weak",
            "confirm_password": "weak"
        }

        # Выполнение
        response = await client.post(
            "v1/register",
            json=registration_data
        )

        # Проверка
        assert response.status_code == 422
        data = response.json()
        assert "errors" in data


    async def test_register_missing_required_fields(
            self,
            client: AsyncClient
    ):
        """Тест регистрации без обязательных полей"""
        test_cases = [
            # Без email
            {
                "phone_number": "+1234567890",
                "password": "SecurePassword123!",
                "confirm_password": "SecurePassword123!"
            },
            # Без password
            {
                "email": "test@example.com",
                "phone_number": "+1234567890",
                "confirm_password": "SecurePassword123!"
            },
            # Без phone_number
            {
                "email": "test@example.com",
                "password": "SecurePassword123!",
                "confirm_password": "SecurePassword123!"
            },
            # Пустой запрос
            {}
        ]

        for registration_data in test_cases:
            response = await client.post(
                "v1/register",
                json=registration_data
            )
            assert response.status_code == 422
            data = response.json()
            assert "errors" in data

    async def test_register_invalid_phone_format(
            self,
            client: AsyncClient
    ):
        """Тест регистрации с невалидным форматом телефона"""
        registration_data = {
            "email": "test@example.com",
            "phone_number": "invalid-phone",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!"
        }

        # Выполнение
        response = await client.post(
            "v1/register",
            json=registration_data
        )

        # Проверка
        assert response.status_code == 422
        data = response.json()
        assert "errors" in data

    async def test_register_sql_injection_attempt(
            self,
            client: AsyncClient
    ):
        """Тест защиты от SQL инъекций при регистрации"""
        registration_data = {
            "email": "test@example.com'; DROP TABLE users; --",
            "phone_number": "+1234567890",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!"
        }

        # Выполнение
        response = await client.post(
            "v1/register",
            json=registration_data
        )

        # Проверка - должна быть ошибка валидации
        assert response.status_code == 422

    async def test_register_xss_attempt(
            self,
            client: AsyncClient
    ):
        """Тест защиты от XSS при регистрации"""
        registration_data = {
            "email": "test@example.com",
            "phone_number": "+1234567890<script>alert('XSS')</script>",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!"
        }

        # Выполнение
        response = await client.post(
            "v1/register",
            json=registration_data
        )

        # Проверка
        assert response.status_code == 422



    async def test_register_special_characters_in_email(
            self,
            client: AsyncClient,
            create_test_role,
            mock_auth_service
    ):

        with patch("deps.get_auth_service", return_value=mock_auth_service):
            # Email с допустимыми спец символами
            registration_data = {
                "email": "test.user+tag@example.com",
                "phone_number": "+1234567890",
                "password": "SecurePassword123!",
                "confirm_password": "SecurePassword123!"
            }

            # Выполнение
            response = await client.post(
                "v1/register",
                json=registration_data
            )

            # Проверка
            assert response.status_code == 200
            data = response.json()
            assert data["email"] == registration_data["email"]

    async def test_register_unicode_in_fields(
            self,
            client: AsyncClient,
            create_test_role,
            mock_auth_service
    ):


        with patch("deps.get_auth_service", return_value=mock_auth_service):
            registration_data = {
                "email": "тест@example.com",  # Кириллица в email
                "phone_number": "+1234567890",
                "password": "SecurePassword123!密碼",  # Unicode в пароле
                "confirm_password": "SecurePassword123!密碼"
            }

            # Выполнение
            response = await client.post(
                "v1/register",
                json=registration_data
            )

            # Проверка - должна быть ошибка валидации для email с кириллицей
            assert response.status_code == 422

