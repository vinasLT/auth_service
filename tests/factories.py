import uuid
from datetime import datetime, UTC

import factory
from factory import LazyFunction, Faker, LazyAttribute
from factory.alchemy import SQLAlchemyModelFactory

from database.models import RefreshToken, UserSession
from database.models.user import User
from faker import Faker as FakerInstance

fake = FakerInstance()


class UserFactory(SQLAlchemyModelFactory):
    class Meta:
        model = User
        sqlalchemy_session_persistence = "flush"

    uuid_key = factory.Faker("uuid4")
    email = factory.Faker("email")
    username = factory.Faker("user_name")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    email_verified = True
    phone_verified = True
    phone_number = factory.Faker("phone_number")
    password_hash = factory.Faker("password")

    is_active = True
    created_at = factory.LazyFunction(lambda: datetime.now(UTC))
    updated_at = factory.LazyFunction(lambda: datetime.now(UTC))


class RefreshTokenFactory(SQLAlchemyModelFactory):
    class Meta:
        model = RefreshToken
        sqlalchemy_session_persistence = "flush"

    # Генерируем уникальный JTI (JWT ID)
    jti = LazyFunction(lambda: str(uuid.uuid4()))

    user_id = Faker('random_int', min=1, max=1000)

    token_family = LazyFunction(lambda: str(uuid.uuid4()))

    # Время выдачи - текущее время
    issued_at = LazyFunction(lambda: datetime.now(UTC))

    # Время истечения - обычно через 7-30 дней
    expires_at = LazyAttribute(
        lambda obj: obj.issued_at + timedelta(days=7)
    )

    # Информация об устройстве и сессии
    device_name = Faker('random_element', elements=[
        'iPhone 15 Pro', 'Samsung Galaxy S24', 'MacBook Pro', 'Chrome Browser',
        'Safari Browser', 'Firefox Browser', 'Android Phone', 'iPad', None
    ])

    user_agent = Faker('user_agent')

    ip_address = Faker('ipv4')

    is_active = True
    revoked_at = None
    used_at = None

    replaced_by_id = None

    @classmethod
    def create_expired(cls, **kwargs):
        """Создает истекший токен"""
        past_time = datetime.now(UTC) - timedelta(days=1)
        kwargs.setdefault('issued_at', past_time - timedelta(hours=1))
        kwargs.setdefault('expires_at', past_time)
        return cls.build(**kwargs)

    @classmethod
    def create_revoked(cls, **kwargs):
        """Создает отозванный токен"""
        kwargs.setdefault('is_active', False)
        kwargs.setdefault('revoked_at', datetime.now(UTC))
        return cls.build(**kwargs)

    @classmethod
    def create_used(cls, **kwargs):
        """Создает использованный токен"""
        kwargs.setdefault('used_at', datetime.now(UTC))
        return cls.build(**kwargs)

    @classmethod
    def create_for_user(cls, user_id, **kwargs):
        """Создает токен для конкретного пользователя"""
        kwargs.setdefault('user_id', user_id)
        return cls.build(**kwargs)

    @classmethod
    def create_family(cls, user_id, count=3, **kwargs):
        """Создает семейство токенов (цепочку обновлений)"""
        tokens = []
        previous_token = None

        for i in range(count):
            token_kwargs = kwargs.copy()
            token_kwargs.setdefault('user_id', user_id)

            if i == 0:
                # Первый токен в семействе
                token = cls.create(**token_kwargs)
            else:
                # Последующие токены заменяют предыдущие
                token_kwargs['replaced_by_id'] = None  # Будет установлено после создания
                token = cls.create(**token_kwargs)

                # Обновляем предыдущий токен
                if previous_token:
                    previous_token.replaced_by_id = token.id
                    previous_token.is_active = False

            tokens.append(token)
            previous_token = token

        return tokens

    @classmethod
    def create_with_custom_expiry(cls, days=7, **kwargs):
        """Создает токен с кастомным временем истечения"""
        issued_at = kwargs.get('issued_at', datetime.now(UTC))
        kwargs.setdefault('expires_at', issued_at + timedelta(days=days))
        return cls(**kwargs)

    @classmethod
    def create_mobile_token(cls, **kwargs):
        """Создает токен для мобильного устройства"""
        kwargs.setdefault('device_name', fake.random_element([
            'iPhone 15 Pro', 'iPhone 14', 'Samsung Galaxy S24',
            'Google Pixel 8', 'OnePlus 11'
        ]))
        kwargs.setdefault('user_agent', fake.random_element([
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B)',
            'MyApp/1.0 (iOS 17.0; iPhone15,3)'
        ]))
        return cls(**kwargs)

    @classmethod
    def create_web_token(cls, **kwargs):
        """Создает токен для веб-браузера"""
        kwargs.setdefault('device_name', fake.random_element([
            'Chrome Browser', 'Firefox Browser', 'Safari Browser',
            'Edge Browser', 'Opera Browser'
        ]))
        kwargs.setdefault('user_agent', fake.chrome())
        return cls(**kwargs)

    @classmethod
    def create_batch_for_user(cls, user_id, count=5, **kwargs):
        """Создает несколько токенов для одного пользователя (разные устройства)"""
        tokens = []
        for i in range(count):
            token_kwargs = kwargs.copy()
            token_kwargs.setdefault('user_id', user_id)
            token_kwargs.setdefault('token_family', str(uuid.uuid4()))  # Разные семейства

            # Варьируем устройства
            if i % 2 == 0:
                token = cls.create_mobile_token(**token_kwargs)
            else:
                token = cls.create_web_token(**token_kwargs)

            tokens.append(token)
        return tokens

from datetime import datetime, timedelta
from factory import Faker, LazyFunction, LazyAttribute
from factory.alchemy import SQLAlchemyModelFactory





class UserSessionFactory(SQLAlchemyModelFactory):
    class Meta:
        model = UserSession
        sqlalchemy_session_persistence = "flush"

    # ID пользователя - строка UUID
    user_id = Faker('uuid4')

    # ID refresh token - может быть None
    refresh_token_id = None

    # Уникальный ключ сессии
    session_key = Faker('uuid4')

    # Время начала сессии - текущее время
    started_at = LazyFunction(lambda: datetime.now(UTC))

    # Последняя активность - текущее время или чуть позже started_at
    last_activity = LazyAttribute(
        lambda obj: obj.started_at + timedelta(
            minutes=fake.random_int(min=0, max=30)
        )
    )

    # Статус активности - по умолчанию активная
    is_active = True

    # Время завершения - по умолчанию None (активная сессия)
    terminated_at = None

    @classmethod
    def create_for_user(cls, user_id, **kwargs):
        """Создает сессию для конкретного пользователя"""
        kwargs.setdefault('user_id', user_id)
        return cls(**kwargs)

    @classmethod
    def create_with_refresh_token(cls, user_id, refresh_token_id, **kwargs):
        """Создает сессию связанную с refresh token"""
        kwargs.setdefault('user_id', user_id)
        kwargs.setdefault('refresh_token_id', refresh_token_id)
        return cls(**kwargs)

    @classmethod
    def create_terminated(cls, **kwargs):
        """Создает завершенную сессию"""
        now = datetime.now(UTC)
        kwargs.setdefault('is_active', False)
        kwargs.setdefault('terminated_at', now)
        # Убеждаемся что started_at и last_activity в прошлом
        if 'started_at' not in kwargs:
            kwargs['started_at'] = now - timedelta(hours=2)
        if 'last_activity' not in kwargs:
            kwargs['last_activity'] = now - timedelta(minutes=30)
        return cls(**kwargs)

    @classmethod
    def create_expired(cls, hours_ago=2, **kwargs):
        """Создает просроченную сессию (неактивную долгое время)"""
        past_time = datetime.now(UTC) - timedelta(hours=hours_ago)
        kwargs.setdefault('started_at', past_time - timedelta(hours=1))
        kwargs.setdefault('last_activity', past_time)
        kwargs.setdefault('is_active', True)  # Технически активная, но давно не использовалась
        return cls(**kwargs)

    @classmethod
    def create_recent_activity(cls, minutes_ago=5, **kwargs):
        """Создает сессию с недавней активностью"""
        recent_time = datetime.now(UTC) - timedelta(minutes=minutes_ago)
        kwargs.setdefault('started_at', recent_time - timedelta(hours=1))
        kwargs.setdefault('last_activity', recent_time)
        kwargs.setdefault('is_active', True)
        return cls(**kwargs)

    @classmethod
    def create_long_running(cls, days_ago=7, **kwargs):
        """Создает долгоживущую сессию"""
        start_time = datetime.now(UTC) - timedelta(days=days_ago)
        kwargs.setdefault('started_at', start_time)
        kwargs.setdefault('last_activity', datetime.now(UTC) - timedelta(minutes=10))
        kwargs.setdefault('is_active', True)
        return cls(**kwargs)

    @classmethod
    def create_batch_for_user(cls, user_id, count=3, **kwargs):
        """Создает несколько сессий для одного пользователя"""
        sessions = []
        for i in range(count):
            session_kwargs = kwargs.copy()
            session_kwargs.setdefault('user_id', user_id)

            # Варьируем время создания сессий
            base_time = datetime.now(UTC) - timedelta(days=i, hours=fake.random_int(0, 23))
            session_kwargs.setdefault('started_at', base_time)

            # Некоторые сессии делаем неактивными
            if i > 0 and fake.boolean(chance_of_getting_true=30):
                session = cls.create_terminated(**session_kwargs)
            else:
                session = cls.create(**session_kwargs)

            sessions.append(session)

        return sessions

    @classmethod
    def create_user_sessions_history(cls, user_id, active_count=2, terminated_count=3, **kwargs):
        """Создает историю сессий пользователя (активные + завершенные)"""
        sessions = []

        # Создаем завершенные сессии (более старые)
        for i in range(terminated_count):
            session_kwargs = kwargs.copy()
            session_kwargs.setdefault('user_id', user_id)

            days_ago = terminated_count - i + 1  # Более старые сессии
            start_time = datetime.now(UTC) - timedelta(days=days_ago)
            end_time = start_time + timedelta(hours=fake.random_int(1, 6))

            session_kwargs.update({
                'started_at': start_time,
                'last_activity': end_time - timedelta(minutes=fake.random_int(1, 30)),
                'terminated_at': end_time,
                'is_active': False
            })

            sessions.append(cls.create(**session_kwargs))

        # Создаем активные сессии (более новые)
        for i in range(active_count):
            session_kwargs = kwargs.copy()
            session_kwargs.setdefault('user_id', user_id)

            days_ago = i  # Более новые сессии
            start_time = datetime.now(UTC) - timedelta(days=days_ago, hours=fake.random_int(1, 12))

            session_kwargs.update({
                'started_at': start_time,
                'last_activity': datetime.now(UTC) - timedelta(minutes=fake.random_int(1, 60)),
                'is_active': True
            })

            sessions.append(cls.create(**session_kwargs))

        return sessions

    @classmethod
    def create_with_pattern(cls, user_id, pattern='daily', days=7, **kwargs):
        """Создает сессии с определенным паттерном активности"""
        sessions = []

        for i in range(days):
            session_kwargs = kwargs.copy()
            session_kwargs.setdefault('user_id', user_id)

            if pattern == 'daily':
                # Ежедневная активность
                start_time = datetime.now(UTC)  - timedelta(days=i, hours=9)  # Начало в 9 утра
                end_time = start_time + timedelta(hours=8)  # 8-часовая сессия

            elif pattern == 'weekend':
                # Активность только по выходным
                if i % 7 not in [5, 6]:  # Пропускаем будни
                    continue
                start_time = datetime.now(UTC)  - timedelta(days=i, hours=10)
                end_time = start_time + timedelta(hours=4)

            elif pattern == 'sporadic':
                # Нерегулярная активность
                if fake.boolean(chance_of_getting_true=40):  # 40% шанс активности
                    continue
                start_time = datetime.now(UTC)  - timedelta(days=i, hours=fake.random_int(6, 22))
                end_time = start_time + timedelta(hours=fake.random_int(1, 6))

            session_kwargs.update({
                'started_at': start_time,
                'last_activity': end_time - timedelta(minutes=fake.random_int(1, 30)),
                'terminated_at': end_time,
                'is_active': False
            })

            sessions.append(cls.create(**session_kwargs))

        return sessions

    @classmethod
    def create_concurrent_sessions(cls, user_id, count=3, **kwargs):
        """Создает несколько одновременных активных сессий для пользователя"""
        sessions = []
        base_start_time = datetime.now(UTC)  - timedelta(hours=2)

        for i in range(count):
            session_kwargs = kwargs.copy()
            session_kwargs.setdefault('user_id', user_id)

            # Все сессии начинаются примерно в одно время
            start_time = base_start_time + timedelta(minutes=fake.random_int(0, 30))

            session_kwargs.update({
                'started_at': start_time,
                'last_activity': datetime.now(UTC) - timedelta(minutes=fake.random_int(1, 15)),
                'is_active': True
            })

            sessions.append(cls.create(**session_kwargs))

        return sessions



