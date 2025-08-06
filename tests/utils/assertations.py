# tests/utils/assertions.py
"""Кастомные assertions для тестов аутентификации"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import json
import re


class AuthAssertions:
    """Специфичные проверки для аутентификации"""

    @staticmethod
    def assert_valid_token_response(response_data: Dict[str, Any]):
        """Проверка корректности ответа с токенами"""
        assert "access_token" in response_data, "Missing access_token in response"
        assert "refresh_token" in response_data, "Missing refresh_token in response"
        assert response_data["access_token"], "Empty access_token"
        assert response_data["refresh_token"], "Empty refresh_token"
        assert response_data["access_token"] != response_data["refresh_token"], \
            "Access and refresh tokens should be different"

    @staticmethod
    def assert_valid_user_response(response_data: Dict[str, Any]):
        """Проверка корректности ответа с данными пользователя"""
        required_fields = ["id", "email", "uuid_key"]
        for field in required_fields:
            assert field in response_data, f"Missing required field: {field}"

        # Проверка, что чувствительные данные не возвращаются
        sensitive_fields = ["password", "password_hash"]
        for field in sensitive_fields:
            assert field not in response_data, f"Sensitive field exposed: {field}"

    @staticmethod
    def assert_error_response(
            response_data: Dict[str, Any],
            expected_detail: Optional[str] = None,
            expected_status: Optional[str] = None
    ):
        """Проверка корректности ответа об ошибке"""
        assert "detail" in response_data, "Missing 'detail' in error response"

        if expected_detail:
            assert expected_detail.lower() in response_data["detail"].lower(), \
                f"Expected '{expected_detail}' in error detail, got: {response_data['detail']}"

        if expected_status:
            assert "status" in response_data, "Missing 'status' in error response"
            assert response_data["status"] == expected_status, \
                f"Expected status '{expected_status}', got: {response_data.get('status')}"

    @staticmethod
    def assert_jwt_structure(token: str):
        """Проверка структуры JWT токена"""
        parts = token.split('.')
        assert len(parts) == 3, f"Invalid JWT structure: expected 3 parts, got {len(parts)}"

        # Проверка, что каждая часть не пустая
        for i, part in enumerate(parts):
            assert part, f"Empty JWT part at position {i}"

    @staticmethod
    def assert_session_active(session):
        """Проверка активности сессии"""
        assert session.is_active is True, "Session is not active"
        assert session.terminated_at is None, "Active session has termination time"
        assert session.last_activity is not None, "Session missing last_activity"

    @staticmethod
    def assert_session_terminated(session):
        """Проверка завершенности сессии"""
        assert session.is_active is False, "Session is still active"
        assert session.terminated_at is not None, "Terminated session missing termination time"

    @staticmethod
    def assert_token_blacklisted(auth_service_mock, token_type: str, jti: str):
        """Проверка, что токен добавлен в blacklist"""
        calls = auth_service_mock.blacklist_token.call_args_list
        blacklisted = any(
            call[0] == (token_type, jti) or
            (len(call[0]) > 1 and call[0][0] == token_type and call[0][1] == jti)
            for call in calls
        )
        assert blacklisted, f"Token {jti} of type {token_type} not blacklisted"

    @staticmethod
    def assert_rate_limit_headers(headers: Dict[str, str]):
        """Проверка заголовков rate limiting"""
        required_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset"
        ]

        for header in required_headers:
            assert header in headers, f"Missing rate limit header: {header}"

        # Проверка значений
        limit = int(headers.get("X-RateLimit-Limit", 0))
        remaining = int(headers.get("X-RateLimit-Remaining", 0))

        assert limit > 0, "Invalid rate limit value"
        assert remaining >= 0, "Invalid remaining requests value"
        assert remaining <= limit, "Remaining requests exceed limit"


class DatabaseAssertions:
    """Проверки состояния базы данных"""

    @staticmethod
    async def assert_user_exists(session, email: str):
        """Проверка существования пользователя"""
        from database.crud.user import UserService
        user_service = UserService(session)
        user = await user_service.get_by_email(email)
        assert user is not None, f"User with email {email} not found"
        return user

    @staticmethod
    async def assert_user_not_exists(session, email: str):
        """Проверка отсутствия пользователя"""
        from database.crud.user import UserService
        user_service = UserService(session)
        user = await user_service.get_by_email(email)
        assert user is None, f"User with email {email} should not exist"

    @staticmethod
    async def assert_refresh_token_exists(session, jti: str):
        """Проверка существования refresh токена"""
        from database.crud.refresh_token import RefreshTokenService
        token_service = RefreshTokenService(session)
        token = await token_service.get_by_jti(jti)
        assert token is not None, f"Refresh token with jti {jti} not found"
        return token

    @staticmethod
    async def assert_session_count(session, user_id: int, expected_count: int):
        """Проверка количества сессий пользователя"""
        from database.crud.user_session import UserSessionService
        session_service = UserSessionService(session)
        sessions = await session_service.get_active_sessions_by_user_id(user_id)
        assert len(sessions) == expected_count, \
            f"Expected {expected_count} sessions, got {len(sessions)}"

    @staticmethod
    async def assert_user_has_role(session, user_id: int, role_name: str):
        """Проверка наличия роли у пользователя"""
        from sqlalchemy import select
        from database.models import UserRole, Role

        result = await session.execute(
            select(UserRole)
            .join(Role)
            .where(UserRole.user_id == user_id)
            .where(Role.name == role_name)
        )
        user_role = result.scalar_one_or_none()
        assert user_role is not None, f"User {user_id} doesn't have role {role_name}"


class SecurityAssertions:
    """Проверки безопасности"""

    @staticmethod
    def assert_password_not_in_response(response_data: Any, password: str):
        """Проверка, что пароль не возвращается в ответе"""
        response_str = json.dumps(response_data) if isinstance(response_data, dict) else str(response_data)
        assert password not in response_str, "Password found in response!"

    @staticmethod
    def assert_no_sql_injection(response_data: Any):
        """Проверка отсутствия признаков SQL инъекции в ответе"""
        response_str = json.dumps(response_data) if isinstance(response_data, dict) else str(response_data)

        sql_patterns = [
            r"(DROP|DELETE|INSERT|UPDATE|SELECT)\s+",
            r"--",
            r"\/\*.*\*\/",
            r"xp_cmdshell",
            r"sp_executesql"
        ]

        for pattern in sql_patterns:
            assert not re.search(pattern, response_str, re.IGNORECASE), \
                f"Potential SQL injection pattern found: {pattern}"

    @staticmethod
    def assert_no_sensitive_data_logged(logger_mock):
        """Проверка, что чувствительные данные не логируются"""
        sensitive_patterns = [
            r"password",
            r"token",
            r"secret",
            r"api[_-]?key"
        ]

        all_logs = []
        for method in ['info', 'debug', 'warning', 'error', 'critical']:
            if hasattr(logger_mock, method):
                mock_method = getattr(logger_mock, method)
                for call in mock_method.call_args_list:
                    all_logs.append(str(call))

        logs_str = ' '.join(all_logs).lower()

        for pattern in sensitive_patterns:
            # Проверяем только значения, не ключи
            matches = re.findall(f'{pattern}["\']?:\s*["\']([^"\']+)["\']', logs_str)
            for match in matches:
                # Игнорируем placeholder значения
                if match not in ['***', 'hidden', 'redacted', '<hidden>']:
                    assert False, f"Sensitive data found in logs: {pattern}={match}"


class ValidationAssertions:
    """Проверки валидации данных"""

    @staticmethod
    def assert_email_valid(email: str):
        """Проверка валидности email"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        assert re.match(email_pattern, email), f"Invalid email format: {email}"

    @staticmethod
    def assert_phone_valid(phone: str):
        """Проверка валидности телефона"""
        phone_pattern = r'^\+?[1-9]\d{7,14}$'
        assert re.match(phone_pattern, phone), f"Invalid phone format: {phone}"

    @staticmethod
    def assert_password_strong(password: str):
        """Проверка силы пароля"""
        assert len(password) >= 8, "Password too short"
        assert re.search(r'[A-Z]', password), "Password missing uppercase letter"
        assert re.search(r'[a-z]', password), "Password missing lowercase letter"
        assert re.search(r'\d', password), "Password missing digit"
        assert re.search(r'[!@#$%^&*(),.?":{}|<>]', password), "Password missing special character"

