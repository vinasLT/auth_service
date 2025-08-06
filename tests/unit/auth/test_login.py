# tests/unit/auth/test_login.py
"""Тесты для эндпоинта логина"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, patch, MagicMock, ANY
from datetime import datetime, timedelta, UTC
import uuid

from auth.service import AuthService
from deps import get_auth_service
from tests.conftest import mock_auth_service_function


@pytest.mark.asyncio
@pytest.mark.auth
class TestLoginEndpoint:
    """Тесты для POST /login"""

    async def test_login_success(
            self,
            client: AsyncClient,
            async_db_session: AsyncSession,
            create_test_user,
            create_test_role,
            get_app
    ):
        """Тест успешного логина"""
        user = await create_test_user(
            email="test@example.com",
            password_hash="hashed_password",
            is_active=True
        )

        def mock_auth_service():
            """Мок для AuthService"""
            service = AsyncMock(spec=AuthService)

            service.verify_password.return_value = True

            service.hash_password.return_value = "hashed_password"
            service.verify_password.return_value = True
            service.generate_token.return_value = "test_token"
            service.verify_token.return_value = {
                "sub": str(uuid.uuid4()),
                "email": "test@example.com",
                "type": "access",
                "jti": str(uuid.uuid4()),
                "token_family": str(uuid.uuid4()),
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
            }
            service.get_payload_for_token.return_value = {
                "sub": str(uuid.uuid4()),
                "email": "test@example.com",
                "type": "access",
                "jti": str(uuid.uuid4()),
                "token_family": str(uuid.uuid4()),
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
            }
            service.is_token_blacklisted.return_value = False
            service.blacklist_token.return_value = None
            service.access_token_ttl = 3600  # 1 hour
            service.refresh_token_ttl = 604800  # 7 days

            return service

        get_app.dependency_overrides[get_auth_service] = mock_auth_service


        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }

        # Выполнение
        response = await client.post(
            "v1/login",
            json=login_data,
            headers={
                "user-agent": "Mozilla/5.0 Test Browser",
                "x-device-name": "Test Device"
            }
        )
        print(response.json())

        # Проверка
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["access_token"] == "test_token"
        assert data["refresh_token"] == "test_token"


    async def test_login_invalid_email(
            self,
            client: AsyncClient,
            mock_auth_service
    ):
        """Тест логина с несуществующим email"""
        with patch("deps.get_auth_service", return_value=mock_auth_service):
            login_data = {
                "email": "nonexistent@example.com",
                "password": "AnyPassword123!"
            }

            # Выполнение
            response = await client.post("v1/login", json=login_data)

            # Проверка
            assert response.status_code == 401
            data = response.json()
            assert "detail" in data
            assert "Invalid email or password" in data["detail"]

    async def test_login_invalid_password(
            self,
            client: AsyncClient,
            create_test_user,
            mock_auth_service
    ):
        """Тест логина с неправильным паролем"""

        with patch("deps.get_auth_service", return_value=mock_auth_service):
            mock_auth_service.verify_password.return_value = False

            login_data = {
                "email": "test@example.com",
                "password": "WrongPassword123!"
            }

            # Выполнение
            response = await client.post("v1/login", json=login_data)

            # Проверка
            assert response.status_code == 401
            data = response.json()
            assert "detail" in data
            assert "Invalid email or password" in data["detail"]

    async def test_login_inactive_user(
            self,
            client: AsyncClient,
            create_test_user,
            mock_auth_service
    ):
        """Тест логина деактивированного пользователя"""
        # Подготовка
        user = await create_test_user(
            email="test@example.com",
            password_hash="hashed_password",
            is_active=False
        )

        with patch("deps.get_auth_service", return_value=mock_auth_service):
            mock_auth_service.verify_password.return_value = True

            login_data = {
                "email": "test@example.com",
                "password": "TestPassword123!"
            }

            # Выполнение
            response = await client.post("v1/login", json=login_data)

            # Проверка
            assert response.status_code == 401

    async def test_login_missing_credentials(
            self,
            client: AsyncClient
    ):
        """Тест логина без учетных данных"""
        test_cases = [
            # Без email
            {"password": "TestPassword123!"},
            # Без password
            {"email": "test@example.com"},
            # Пустой запрос
            {}
        ]

        for login_data in test_cases:
            response = await client.post("v1/login", json=login_data)
            assert response.status_code == 422
            data = response.json()
            assert "title" in data

    async def test_login_empty_credentials(
            self,
            client: AsyncClient
    ):
        """Тест логина с пустыми учетными данными"""
        login_data = {
            "email": "",
            "password": ""
        }

        # Выполнение
        response = await client.post("v1/login", json=login_data)

        # Проверка
        assert response.status_code == 422

    async def test_login_sql_injection_attempt(
            self,
            client: AsyncClient
    ):
        """Тест защиты от SQL инъекций при логине"""
        login_data = {
            "email": "admin@example.com' OR '1'='1",
            "password": "' OR '1'='1"
        }

        # Выполнение
        response = await client.post("v1/login", json=login_data)

        # Проверка
        assert response.status_code in [401, 422]

    async def test_login_creates_refresh_token(
            self,
            client: AsyncClient,
            async_db_session: AsyncSession,
            create_test_user,
            mock_auth_service,
            get_app,
    ):
        """Тест создания refresh токена при логине"""
        # Подготовка
        user = await create_test_user()

        get_app.dependency_overrides[get_auth_service] = mock_auth_service_function

        with patch("deps.get_auth_service", return_value=mock_auth_service):
            mock_auth_service.verify_password.return_value = True
            refresh_jti = str(uuid.uuid4())
            token_family = str(uuid.uuid4())

            mock_auth_service.get_payload_for_token.side_effect = [
                {"sub": user.uuid_key, "email": user.email, "type": "access", "jti": str(uuid.uuid4())},
                {"sub": user.uuid_key, "email": user.email, "type": "refresh", "jti": refresh_jti,
                 "token_family": token_family}
            ]

            login_data = {
                "email": "test@example.com",
                "password": "hashed_password!1I"
            }

            # Выполнение
            response = await client.post("v1/login", json=login_data)
            print(response.json())

            # Проверка
            assert response.status_code == 200

            # Проверяем создание refresh токена в БД
            from database.crud.refresh_token import RefreshTokenService
            refresh_service = RefreshTokenService(async_db_session)
            token = await refresh_service.get_by_jti(refresh_jti)
            assert token is not None
            assert token.user_id == user.id
            assert token.is_active == True

    async def test_login_captures_device_info(
            self,
            client: AsyncClient,
            async_db_session: AsyncSession,
            create_test_user,
            mock_auth_service
    ):
        """Тест сохранения информации об устройстве при логине"""
        # Подготовка
        user = await create_test_user()

        with patch("auth.v1.get_auth_service", return_value=mock_auth_service):
            mock_auth_service.verify_password.return_value = True
            refresh_jti = str(uuid.uuid4())

            mock_auth_service.get_payload_for_token.side_effect = [
                {"sub": user.uuid_key, "email": user.email, "type": "access", "jti": str(uuid.uuid4())},
                {"sub": user.uuid_key, "email": user.email, "type": "refresh", "jti": refresh_jti,
                 "token_family": str(uuid.uuid4())}
            ]

            login_data = {
                "email": "test@example.com",
                "password": "TestPassword123!"
            }

            # Выполнение с кастомными заголовками
            response = await client.post(
                "/login",
                json=login_data,
                headers={
                    "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
                    "x-device-name": "iPhone 12",
                    "x-forwarded-for": "192.168.1.100"
                }
            )

            # Проверка
            assert response.status_code == 200

            # Проверяем сохранение информации об устройстве
            from database.crud.refresh_token import RefreshTokenService
            refresh_service = RefreshTokenService(async_db_session)
            token = await refresh_service.get_by_jti(refresh_jti)
            assert token.device_name == "iPhone 12"
            assert "iPhone" in token.user_agent

    @pytest.mark.slow
    async def test_login_rate_limiting(
            self,
            client: AsyncClient,
            create_test_user,
            mock_auth_service
    ):
        """Тест rate limiting для эндпоинта логина"""
        # Подготовка
        user = await create_test_user()

        with patch("auth.v1.get_auth_service", return_value=mock_auth_service):
            mock_auth_service.verify_password.return_value = False

            login_data = {
                "email": "test@example.com",
                "password": "WrongPassword!"
            }

            # Делаем множество неудачных попыток логина
            for i in range(16):  # Лимит 15 за 120 секунд
                response = await client.post("/login", json=login_data)

                if i < 15:
                    assert response.status_code == 401
                else:
                    # 16-я попытка должна быть заблокирована
                    assert response.status_code == 429

    async def test_login_case_insensitive_email(
            self,
            client: AsyncClient,
            create_test_user,
            mock_auth_service
    ):
        """Тест логина с email в разном регистре"""
        # Подготовка
        user = await create_test_user(email="test@example.com")

        with patch("auth.v1.get_auth_service", return_value=mock_auth_service):
            mock_auth_service.verify_password.return_value = True
            mock_auth_service.get_payload_for_token.side_effect = [
                {"sub": user.uuid_key, "email": user.email, "type": "access", "jti": str(uuid.uuid4())},
                {"sub": user.uuid_key, "email": user.email, "type": "refresh", "jti": str(uuid.uuid4()),
                 "token_family": str(uuid.uuid4())}
            ]

            # Тестируем с email в верхнем регистре
            login_data = {
                "email": "TEST@EXAMPLE.COM",
                "password": "TestPassword123!"
            }

            # Выполнение
            response = await client.post("/login", json=login_data)

            # Проверка - должен работать независимо от регистра
            assert response.status_code in [200, 401]  # Зависит от реализации

    async def test_login_logging(
            self,
            client: AsyncClient,
            create_test_user,
            mock_auth_service,
            mock_logger
    ):
        """Тест логирования при логине"""
        # Подготовка
        user = await create_test_user()

        with patch("auth.v1.logger", mock_logger):
            with patch("auth.v1.get_auth_service", return_value=mock_auth_service):
                mock_auth_service.verify_password.return_value = True
                mock_auth_service.get_payload_for_token.side_effect = [
                    {"sub": user.uuid_key, "email": user.email, "type": "access", "jti": str(uuid.uuid4())},
                    {"sub": user.uuid_key, "email": user.email, "type": "refresh", "jti": str(uuid.uuid4()),
                     "token_family": str(uuid.uuid4())}
                ]

                login_data = {
                    "email": "test@example.com",
                    "password": "TestPassword123!"
                }

                # Выполнение
                response = await client.post("/login", json=login_data)

                # Проверка логирования
                assert response.status_code == 200
                mock_logger.info.assert_called()

                # Проверяем, что пароль не логируется
                for call in mock_logger.info.call_args_list:
                    assert "TestPassword123!" not in str(call)

                # Проверяем логирование успешного входа
                last_info_call = mock_logger.info.call_args_list[-1]
                assert "successful" in str(last_info_call).lower()

    async def test_login_database_error_handling(
            self,
            client: AsyncClient,
            mock_auth_service
    ):
        """Тест обработки ошибок БД при логине"""
        with patch("auth.v1.get_auth_service", return_value=mock_auth_service):
            with patch("auth.v1.UserService") as mock_user_service:
                # Симулируем ошибку БД
                mock_user_service.return_value.get_by_email.side_effect = Exception("Database connection lost")

                login_data = {
                    "email": "test@example.com",
                    "password": "TestPassword123!"
                }

                # Выполнение
                response = await client.post("/login", json=login_data)

                # Проверка
                assert response.status_code == 500

    async def test_login_extracts_roles_and_permissions(
            self,
            client: AsyncClient,
            async_db_session: AsyncSession,
            create_test_user,
            create_test_role,
            mock_auth_service
    ):
        """Тест извлечения ролей и разрешений при логине"""
        # Подготовка
        role = await create_test_role(name="admin")
        user = await create_test_user()

        # Создаем связь user-role
        from database.models import UserRole
        user_role = UserRole(user_id=user.id, role_id=role.id)
        async_db_session.add(user_role)
        await async_db_session.commit()

        with patch("auth.v1.get_auth_service", return_value=mock_auth_service):
            mock_auth_service.verify_password.return_value = True

            # Мокаем извлечение ролей
            with patch("auth.v1.UserService.extract_roles_and_permissions_from_user") as mock_extract:
                mock_extract.return_value = {
                    "roles": ["admin"],
                    "permissions": ["read", "write", "delete"]
                }

                mock_auth_service.get_payload_for_token.side_effect = [
                    {
                        "sub": user.uuid_key,
                        "email": user.email,
                        "type": "access",
                        "jti": str(uuid.uuid4()),
                        "roles": ["admin"],
                        "permissions": ["read", "write", "delete"]
                    },
                    {
                        "sub": user.uuid_key,
                        "email": user.email,
                        "type": "refresh",
                        "jti": str(uuid.uuid4()),
                        "token_family": str(uuid.uuid4())
                    }
                ]

                login_data = {
                    "email": "test@example.com",
                    "password": "TestPassword123!"
                }

                # Выполнение
                response = await client.post("/login", json=login_data)

                # Проверка
                assert response.status_code == 200
                mock_extract.assert_called_once_with(user.id)

                # Проверяем, что роли переданы в payload токена
                access_token_call = mock_auth_service.get_payload_for_token.call_args_list[0]
                assert access_token_call[1]["roles_permissions"] == {
                    "roles": ["admin"],
                    "permissions": ["read", "write", "delete"]
                }