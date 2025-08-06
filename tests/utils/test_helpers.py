# tests/utils/test_helpers.py
"""Вспомогательные функции и утилиты для тестов"""

import jwt
import json
import hashlib
import secrets
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, UTC
import uuid
from unittest.mock import MagicMock, AsyncMock


class TokenHelper:
    """Утилиты для работы с токенами в тестах"""

    @staticmethod
    def create_test_jwt(
            payload: Dict[str, Any],
            secret: str = "test_secret",
            algorithm: str = "HS256",
            expires_in: Optional[timedelta] = None
    ) -> str:
        """Создание тестового JWT токена"""
        if expires_in:
            payload["exp"] = int((datetime.now(UTC) + expires_in).timestamp())
        if "iat" not in payload:
            payload["iat"] = int(datetime.now(UTC).timestamp())

        return jwt.encode(payload, secret, algorithm=algorithm)

    @staticmethod
    def decode_test_jwt(
            token: str,
            secret: str = "test_secret",
            algorithm: str = "HS256"
    ) -> Dict[str, Any]:
        """Декодирование тестового JWT токена"""
        return jwt.decode(token, secret, algorithms=[algorithm])

    @staticmethod
    def create_expired_token(
            payload: Dict[str, Any],
            expired_since: timedelta = timedelta(hours=1)
    ) -> str:
        """Создание истекшего токена"""
        payload["exp"] = int((datetime.now(UTC) - expired_since).timestamp())
        payload["iat"] = int((datetime.now(UTC) - expired_since - timedelta(hours=1)).timestamp())
        return TokenHelper.create_test_jwt(payload)

    @staticmethod
    def extract_jti_from_token(token: str) -> Optional[str]:
        """Извлечение JTI из токена без проверки подписи"""
        try:
            # Декодируем без проверки подписи для тестов
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload.get("jti")
        except:
            return None


class PasswordHelper:
    """Утилиты для работы с паролями в тестах"""

    @staticmethod
    def hash_password(password: str) -> str:
        """Простое хеширование пароля для тестов"""
        # В реальности используется bcrypt, но для тестов достаточно простого хеша
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def generate_strong_password() -> str:
        """Генерация сильного пароля"""
        return f"Test{secrets.token_urlsafe(8)}!@#123"

    @staticmethod
    def generate_weak_passwords() -> List[str]:
        """Генерация списка слабых паролей для тестирования валидации"""
        return [
            "123456",  # Слишком простой
            "password",  # Слишком распространенный
            "abc",  # Слишком короткий
            "12345678",  # Только цифры
            "abcdefgh",  # Только буквы
            "        ",  # Только пробелы
            "",  # Пустой
        ]


class RequestHelper:
    """Утилиты для создания тестовых запросов"""

    @staticmethod
    def create_auth_headers(token: str) -> Dict[str, str]:
        """Создание заголовков с авторизацией"""
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    @staticmethod
    def create_device_headers(
            device_name: str = "Test Device",
            user_agent: str = "Test User Agent",
            ip_address: str = "127.0.0.1"
    ) -> Dict[str, str]:
        """Создание заголовков с информацией об устройстве"""
        return {
            "x-device-name": device_name,
            "user-agent": user_agent,
            "x-forwarded-for": ip_address
        }

    @staticmethod
    def create_rate_limit_headers(
            remaining: int = 10,
            reset_time: Optional[datetime] = None
    ) -> Dict[str, str]:
        """Создание заголовков rate limit для тестирования"""
        if reset_time is None:
            reset_time = datetime.now(UTC) + timedelta(minutes=1)

        return {
            "X-RateLimit-Limit": "15",
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(reset_time.timestamp()))
        }


class DatabaseHelper:
    """Утилиты для работы с БД в тестах"""

    @staticmethod
    async def count_records(session, model_class) -> int:
        """Подсчет записей в таблице"""
        from sqlalchemy import select, func
        result = await session.execute(select(func.count()).select_from(model_class))
        return result.scalar()

    @staticmethod
    async def clear_table(session, model_class):
        """Очистка таблицы"""
        from sqlalchemy import delete
        await session.execute(delete(model_class))
        await session.commit()

    @staticmethod
    async def create_bulk_users(session, count: int = 10) -> List:
        """Создание множества тестовых пользователей"""
        from database.models import User
        users = []

        for i in range(count):
            user = User(
                uuid_key=str(uuid.uuid4()),
                email=f"user{i}@example.com",
                username=f"user{i}",
                password_hash=PasswordHelper.hash_password(f"Password{i}!"),
                phone_number=f"+123456789{i}",
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            session.add(user)
            users.append(user)

        await session.commit()
        return users


class MockHelper:
    """Утилиты для создания моков"""

    @staticmethod
    def create_mock_redis() -> AsyncMock:
        """Создание мока Redis клиента"""
        redis_mock = AsyncMock()

        # Внутреннее хранилище для имитации Redis
        storage = {}

        async def mock_get(key):
            return storage.get(key)

        async def mock_setex(key, ttl, value):
            storage[key] = value
            return True

        async def mock_exists(key):
            return key in storage

        async def mock_delete(key):
            if key in storage:
                del storage[key]
                return 1
            return 0

        redis_mock.get = AsyncMock(side_effect=mock_get)
        redis_mock.setex = AsyncMock(side_effect=mock_setex)
        redis_mock.exists = AsyncMock(side_effect=mock_exists)
        redis_mock.delete = AsyncMock(side_effect=mock_delete)

        return redis_mock

    @staticmethod
    def create_mock_email_service() -> AsyncMock:
        """Создание мока сервиса отправки email"""
        email_mock = AsyncMock()

        # Список отправленных писем для проверки
        sent_emails = []

        async def mock_send_email(to: str, subject: str, body: str):
            sent_emails.append({
                "to": to,
                "subject": subject,
                "body": body,
                "sent_at": datetime.now(UTC)
            })
            return True

        email_mock.send_email = AsyncMock(side_effect=mock_send_email)
        email_mock.sent_emails = sent_emails

        return email_mock

    @staticmethod
    def create_mock_logger() -> MagicMock:
        """Создание мока логгера с отслеживанием вызовов"""
        logger = MagicMock()

        # Хранилище для логов
        log_records = {
            "debug": [],
            "info": [],
            "warning": [],
            "error": [],
            "critical": []
        }

        def create_log_method(level):
            def log_method(message, *args, **kwargs):
                log_records[level].append({
                    "message": message,
                    "args": args,
                    "kwargs": kwargs,
                    "timestamp": datetime.now(UTC)
                })

            return MagicMock(side_effect=log_method)

        logger.debug = create_log_method("debug")
        logger.info = create_log_method("info")
        logger.warning = create_log_method("warning")
        logger.error = create_log_method("error")
        logger.critical = create_log_method("critical")
        logger.log_records = log_records

        return logger


class ValidationHelper:
    """Утилиты для валидации данных в тестах"""

    @staticmethod
    def is_valid_uuid(value: str) -> bool:
        """Проверка валидности UUID"""
        try:
            uuid.UUID(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Простая проверка валидности email"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def is_valid_phone(phone: str) -> bool:
        """Проверка валидности телефонного номера"""
        import re
        pattern = r'^\+?[1-9]\d{7,14}$'
        return re.match(pattern, phone) is not None

    @staticmethod
    def is_valid_jwt(token: str) -> bool:
        """Проверка формата JWT токена"""
        parts = token.split('.')
        return len(parts) == 3


class AssertionHelper:
    """Дополнительные assertion методы для тестов"""

    @staticmethod
    def assert_datetime_close(
            dt1: datetime,
            dt2: datetime,
            max_delta: timedelta = timedelta(seconds=1)
    ):
        """Проверка близости двух datetime"""
        delta = abs(dt1 - dt2)
        assert delta <= max_delta, f"Datetime difference {delta} exceeds max {max_delta}"

    @staticmethod
    def assert_contains_all(container: Any, items: List[Any]):
        """Проверка наличия всех элементов в контейнере"""
        for item in items:
            assert item in container, f"Item {item} not found in container"

    @staticmethod
    def assert_json_equal(json1: str, json2: str):
        """Сравнение JSON строк"""
        obj1 = json.loads(json1) if isinstance(json1, str) else json1
        obj2 = json.loads(json2) if isinstance(json2, str) else json2
        assert obj1 == obj2, f"JSON objects not equal: {obj1} != {obj2}"

    @staticmethod
    def assert_response_ok(response):
        """Проверка успешного ответа"""
        assert response.status_code in range(200, 300), \
            f"Response not OK: {response.status_code} - {response.text}"

    @staticmethod
    def assert_response_error(response, expected_status: Optional[int] = None):
        """Проверка ошибочного ответа"""
        assert response.status_code >= 400, \
            f"Expected error response, got: {response.status_code}"

        if expected_status:
            assert response.status_code == expected_status, \
                f"Expected status {expected_status}, got {response.status_code}"


class DataGenerator:
    """Генератор тестовых данных"""

    @staticmethod
    def generate_user_data(index: int = 0) -> Dict[str, str]:
        """Генерация данных пользователя"""
        return {
            "email": f"testuser{index}@example.com",
            "username": f"testuser{index}",
            "phone_number": f"+1234567890{index:03d}",
            "password": f"TestPassword{index}!@#",
            "confirm_password": f"TestPassword{index}!@#"
        }

    @staticmethod
    def generate_login_data(email: str = "test@example.com") -> Dict[str, str]:
        """Генерация данных для логина"""
        return {
            "email": email,
            "password": "TestPassword123!"
        }

    @staticmethod
    def generate_token_payload(
            user_uuid: Optional[str] = None,
            email: str = "test@example.com",
            token_type: str = "access"
    ) -> Dict[str, Any]:
        """Генерация payload для токена"""
        if user_uuid is None:
            user_uuid = str(uuid.uuid4())

        base_payload = {
            "sub": user_uuid,
            "email": email,
            "type": token_type,
            "jti": str(uuid.uuid4()),
            "iat": int(datetime.now(UTC).timestamp())
        }

        if token_type == "access":
            base_payload.update({
                "roles": ["user"],
                "permissions": ["read"],
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
            })
        elif token_type == "refresh":
            base_payload.update({
                "token_family": str(uuid.uuid4()),
                "exp": int((datetime.now(UTC) + timedelta(days=7)).timestamp())
            })

        return base_payload


class TestDataCleaner:
    """Утилиты для очистки тестовых данных"""

    @staticmethod
    async def cleanup_test_users(session, email_pattern: str = "test%@example.com"):
        """Удаление тестовых пользователей"""
        from sqlalchemy import delete
        from database.models import User

        stmt = delete(User).where(User.email.like(email_pattern))
        await session.execute(stmt)
        await session.commit()

    @staticmethod
    async def cleanup_test_sessions(session, user_id: Optional[int] = None):
        """Удаление тестовых сессий"""
        from sqlalchemy import delete
        from database.models import UserSession

        stmt = delete(UserSession)
        if user_id:
            stmt = stmt.where(UserSession.user_id == user_id)

        await session.execute(stmt)
        await session.commit()

    @staticmethod
    async def cleanup_all_test_data(session):
        """Полная очистка всех тестовых данных"""
        # Очищаем в правильном порядке из-за foreign keys
        from database.models import UserSession, RefreshToken, UserRole, User, Role

        for model in [UserSession, RefreshToken, UserRole, User, Role]:
            await DatabaseHelper.clear_table(session, model)