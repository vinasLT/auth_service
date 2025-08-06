# tests/factories/user_factory.py
"""Фабрики для создания тестовых данных пользователей"""

import factory
from datetime import datetime, UTC, timedelta
import uuid
from typing import Dict, Any

from database.models import User, Role, UserRole, RefreshToken, UserSession, Permission, RolePermission


class UserFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Фабрика для создания тестовых пользователей"""

    class Meta:
        model = User
        sqlalchemy_session_persistence = "commit"

    id = factory.Sequence(lambda n: n + 1)
    uuid_key = factory.LazyFunction(lambda: str(uuid.uuid4()))
    email = factory.Sequence(lambda n: f"user{n}@example.com")
    username = factory.LazyAttribute(lambda obj: obj.email.split('@')[0])
    password_hash = factory.LazyFunction(lambda: "hashed_password_$2b$12$...")
    phone_number = factory.Sequence(lambda n: f"+1234567890{n:03d}")
    is_active = True
    is_verified = False
    created_at = factory.LazyFunction(lambda: datetime.now(UTC))
    updated_at = factory.LazyFunction(lambda: datetime.now(UTC))

    @factory.post_generation
    def roles(self, create, extracted, **kwargs):
        """Добавление ролей после создания пользователя"""
        if not create:
            return

        if extracted:
            for role in extracted:
                UserRoleFactory(user=self, role=role)

    @classmethod
    def create_with_role(cls, role_name: str = "user", **kwargs):
        """Создание пользователя с определенной ролью"""
        user = cls.create(**kwargs)
        role = RoleFactory.create(name=role_name)
        UserRoleFactory.create(user=user, role=role)
        return user

    @classmethod
    def create_admin(cls, **kwargs):
        """Создание пользователя с ролью admin"""
        return cls.create_with_role("admin", **kwargs)

    @classmethod
    def create_inactive(cls, **kwargs):
        """Создание неактивного пользователя"""
        kwargs['is_active'] = False
        return cls.create(**kwargs)


class RoleFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Фабрика для создания ролей"""

    class Meta:
        model = Role
        sqlalchemy_session_persistence = "commit"

    id = factory.Sequence(lambda n: n + 1)
    name = factory.Sequence(lambda n: f"role_{n}")
    description = factory.LazyAttribute(lambda obj: f"Description for {obj.name}")
    is_default = False
    created_at = factory.LazyFunction(lambda: datetime.now(UTC))
    updated_at = factory.LazyFunction(lambda: datetime.now(UTC))

    @factory.post_generation
    def permissions(self, create, extracted, **kwargs):
        """Добавление разрешений после создания роли"""
        if not create:
            return

        if extracted:
            for permission in extracted:
                RolePermissionFactory(role=self, permission=permission)

    @classmethod
    def create_default(cls, **kwargs):
        """Создание дефолтной роли"""
        kwargs['is_default'] = True
        kwargs['name'] = kwargs.get('name', 'user')
        return cls.create(**kwargs)


class PermissionFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Фабрика для создания разрешений"""

    class Meta:
        model = Permission
        sqlalchemy_session_persistence = "commit"

    id = factory.Sequence(lambda n: n + 1)
    name = factory.Sequence(lambda n: f"permission_{n}")
    resource = factory.LazyAttribute(lambda obj: obj.name.split('_')[0])
    action = factory.LazyAttribute(lambda obj: "read")
    description = factory.LazyAttribute(lambda obj: f"Permission to {obj.action} {obj.resource}")
    created_at = factory.LazyFunction(lambda: datetime.now(UTC))
    updated_at = factory.LazyFunction(lambda: datetime.now(UTC))

    @classmethod
    def create_crud_permissions(cls, resource: str):
        """Создание CRUD разрешений для ресурса"""
        actions = ["create", "read", "update", "delete"]
        permissions = []

        for action in actions:
            permission = cls.create(
                name=f"{resource}_{action}",
                resource=resource,
                action=action
            )
            permissions.append(permission)

        return permissions


class UserRoleFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Фабрика для связи пользователь-роль"""

    class Meta:
        model = UserRole
        sqlalchemy_session_persistence = "commit"

    user = factory.SubFactory(UserFactory)
    role = factory.SubFactory(RoleFactory)
    assigned_at = factory.LazyFunction(lambda: datetime.now(UTC))


class RolePermissionFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Фабрика для связи роль-разрешение"""

    class Meta:
        model = RolePermission
        sqlalchemy_session_persistence = "commit"

    role = factory.SubFactory(RoleFactory)
    permission = factory.SubFactory(PermissionFactory)


class RefreshTokenFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Фабрика для создания refresh токенов"""

    class Meta:
        model = RefreshToken
        sqlalchemy_session_persistence = "commit"

    id = factory.Sequence(lambda n: n + 1)
    jti = factory.LazyFunction(lambda: str(uuid.uuid4()))
    user = factory.SubFactory(UserFactory)
    user_id = factory.LazyAttribute(lambda obj: obj.user.id)
    token_family = factory.LazyFunction(lambda: str(uuid.uuid4()))
    issued_at = factory.LazyFunction(lambda: datetime.now(UTC))
    expires_at = factory.LazyFunction(
        lambda: datetime.now(UTC) + timedelta(days=7)
    )
    device_name = factory.Faker('user_agent')
    user_agent = factory.Faker('user_agent')
    ip_address = factory.Faker('ipv4')
    is_active = True
    revoked_at = None

    @classmethod
    def create_expired(cls, **kwargs):
        """Создание истекшего токена"""
        kwargs['expires_at'] = datetime.now(UTC) - timedelta(days=1)
        kwargs['is_active'] = False
        return cls.create(**kwargs)

    @classmethod
    def create_revoked(cls, **kwargs):
        """Создание отозванного токена"""
        kwargs['is_active'] = False
        kwargs['revoked_at'] = datetime.now(UTC)
        return cls.create(**kwargs)

    @classmethod
    def create_family(cls, user, count: int = 3):
        """Создание семьи токенов (цепочки ротации)"""
        token_family = str(uuid.uuid4())
        tokens = []

        for i in range(count):
            is_active = (i == count - 1)  # Только последний активен
            token = cls.create(
                user=user,
                token_family=token_family,
                is_active=is_active,
                issued_at=datetime.now(UTC) - timedelta(hours=count - i)
            )
            tokens.append(token)

        return tokens


class UserSessionFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Фабрика для создания сессий пользователей"""

    class Meta:
        model = UserSession
        sqlalchemy_session_persistence = "commit"

    id = factory.Sequence(lambda n: n + 1)
    user = factory.SubFactory(UserFactory)
    user_id = factory.LazyAttribute(lambda obj: obj.user.id)
    session_key = factory.LazyFunction(lambda: str(uuid.uuid4()))
    refresh_token = factory.SubFactory(RefreshTokenFactory)
    refresh_token_id = factory.LazyAttribute(lambda obj: obj.refresh_token.id)
    created_at = factory.LazyFunction(lambda: datetime.now(UTC))
    last_activity = factory.LazyFunction(lambda: datetime.now(UTC))
    is_active = True
    terminated_at = None

    @classmethod
    def create_terminated(cls, **kwargs):
        """Создание завершенной сессии"""
        kwargs['is_active'] = False
        kwargs['terminated_at'] = datetime.now(UTC)
        return cls.create(**kwargs)

    @classmethod
    def create_with_refresh_token(cls, user, **kwargs):
        """Создание сессии с refresh токеном"""
        refresh_token = RefreshTokenFactory.create(user=user)
        return cls.create(
            user=user,
            refresh_token=refresh_token,
            **kwargs
        )


class TestDataBuilder:
    """Строитель комплексных тестовых данных"""

    @staticmethod
    def create_authenticated_user_with_session() -> Dict[str, Any]:
        """Создание полностью настроенного аутентифицированного пользователя"""
        # Создаем роль
        user_role = RoleFactory.create_default()
        admin_role = RoleFactory.create(name="admin")

        # Создаем разрешения
        user_permissions = PermissionFactory.create_crud_permissions("profile")
        admin_permissions = PermissionFactory.create_crud_permissions("users")

        # Связываем разрешения с ролями
        for perm in user_permissions[:2]:  # read, update для user роли
            RolePermissionFactory.create(role=user_role, permission=perm)

        for perm in admin_permissions:  # все для admin роли
            RolePermissionFactory.create(role=admin_role, permission=perm)

        # Создаем пользователя
        user = UserFactory.create()
        UserRoleFactory.create(user=user, role=user_role)

        # Создаем refresh токен
        refresh_token = RefreshTokenFactory.create(user=user)

        # Создаем сессию
        session = UserSessionFactory.create(
            user=user,
            refresh_token=refresh_token
        )

        return {
            "user": user,
            "roles": [user_role],
            "permissions": user_permissions[:2],
            "refresh_token": refresh_token,
            "session": session
        }

    @staticmethod
    def create_user_with_multiple_sessions(session_count: int = 3) -> Dict[str, Any]:
        """Создание пользователя с несколькими активными сессиями"""
        user = UserFactory.create()
        sessions = []
        tokens = []

        for i in range(session_count):
            refresh_token = RefreshTokenFactory.create(
                user=user,
                device_name=f"Device {i + 1}",
                ip_address=f"192.168.1.{i + 1}"
            )
            session = UserSessionFactory.create(
                user=user,
                refresh_token=refresh_token
            )
            sessions.append(session)
            tokens.append(refresh_token)

        return {
            "user": user,
            "sessions": sessions,
            "refresh_tokens": tokens
        }

    @staticmethod
    def create_user_with_token_family() -> Dict[str, Any]:
        """Создание пользователя с семьей токенов (история ротации)"""
        user = UserFactory.create()
        tokens = RefreshTokenFactory.create_family(user, count=5)

        # Создаем сессию с последним (активным) токеном
        session = UserSessionFactory.create(
            user=user,
            refresh_token=tokens[-1]
        )

        return {
            "user": user,
            "token_family": tokens[0].token_family,
            "tokens": tokens,
            "active_token": tokens[-1],
            "session": session
        }

    @staticmethod
    def create_test_environment() -> Dict[str, Any]:
        """Создание полного тестового окружения"""
        # Роли
        default_role = RoleFactory.create_default(name="user")
        admin_role = RoleFactory.create(name="admin")
        moderator_role = RoleFactory.create(name="moderator")

        # Разрешения
        user_perms = PermissionFactory.create_crud_permissions("profile")
        post_perms = PermissionFactory.create_crud_permissions("posts")
        admin_perms = PermissionFactory.create_crud_permissions("admin")

        # Связи роль-разрешение
        for perm in user_perms[:2]:  # read, update
            RolePermissionFactory.create(role=default_role, permission=perm)

        for perm in post_perms:  # все CRUD для posts
            RolePermissionFactory.create(role=moderator_role, permission=perm)

        for perm in admin_perms:  # все для admin
            RolePermissionFactory.create(role=admin_role, permission=perm)

        # Пользователи
        regular_user = UserFactory.create()
        UserRoleFactory.create(user=regular_user, role=default_role)

        moderator = UserFactory.create(email="moderator@example.com")
        UserRoleFactory.create(user=moderator, role=moderator_role)

        admin = UserFactory.create(email="admin@example.com")
        UserRoleFactory.create(user=admin, role=admin_role)

        inactive_user = UserFactory.create_inactive(email="inactive@example.com")

        # Сессии и токены
        for user in [regular_user, moderator, admin]:
            refresh_token = RefreshTokenFactory.create(user=user)
            UserSessionFactory.create(user=user, refresh_token=refresh_token)

        return {
            "roles": {
                "default": default_role,
                "admin": admin_role,
                "moderator": moderator_role
            },
            "permissions": {
                "user": user_perms,
                "posts": post_perms,
                "admin": admin_perms
            },
            "users": {
                "regular": regular_user,
                "moderator": moderator,
                "admin": admin,
                "inactive": inactive_user
            }
        }