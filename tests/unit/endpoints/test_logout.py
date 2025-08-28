import pytest
from datetime import datetime, UTC, timedelta

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from dependencies.security import get_current_user
from tests.factories.token_session_user_factories import UserFactory, RefreshTokenFactory, UserSessionFactory


@pytest.mark.asyncio
class TestLogout:
    async def test_logout_success(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        user = UserFactory.build()
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем refresh-токен
        refresh_token = RefreshTokenFactory.build(user_id=user.id)
        session.add(refresh_token)
        await session.commit()
        await session.refresh(refresh_token)

        # Создаем сессию пользователя
        user_session = UserSessionFactory.build(
            user_id=str(user.uuid_key),
            refresh_token_id=refresh_token.id
        )
        session.add(user_session)
        await session.commit()
        await session.refresh(user_session)

        # Мокаем get_current_user dependency
        mock_current_user_data = {
            "sub": str(user.uuid_key),
            "jti": "mock-access-jti",
            "email": user.email,
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Настраиваем mock_auth_service
        mock_auth_service.verify_token.return_value = {
            "sub": str(user.uuid_key),
            "jti": refresh_token.jti,
            "type": "refresh",
            "token_family": refresh_token.token_family
        }
        mock_auth_service.blacklist_token.return_value = None

        # Подготавливаем запрос
        payload = {"refresh_token": "mock-refresh-token"}

        try:
            # Вызываем endpoint
            response = await client.post("/v1/logout", json=payload)

            # Проверяем ответ
            assert response.status_code == 200
            assert response.json() == {"message": "Successfully logged out"}

            # Проверяем вызовы
            mock_auth_service.verify_token.assert_called_once_with("mock-refresh-token")
            mock_auth_service.blacklist_token.assert_any_call('access', 'mock-access-jti')
            mock_auth_service.blacklist_token.assert_any_call('refresh', refresh_token.jti)

            # Проверяем обновление сессии
            await session.refresh(user_session)
            assert user_session.is_active is False
            assert user_session.terminated_at is not None

        finally:
            # Очищаем dependency overrides
            get_app.dependency_overrides.clear()

    async def test_logout_invalid_refresh_token(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        """Тест logout с невалидным refresh token"""
        # Создаем пользователя
        user = UserFactory.build()
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Мокаем get_current_user dependency
        mock_current_user_data = {
            "sub": str(user.uuid_key),
            "jti": str(uuid.uuid4()),
            "email": user.email,
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Симулируем ошибку при верификации токена
        mock_auth_service.verify_token.side_effect = Exception("Invalid token")

        payload = {"refresh_token": "invalid-refresh-token"}

        try:
            response = await client.post("/v1/logout", json=payload)
            assert response.status_code == 500
        finally:
            get_app.dependency_overrides.clear()

    async def test_logout_refresh_token_not_found(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        """Тест logout когда refresh token не найден в БД"""
        # Создаем пользователя
        user = UserFactory.build()
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Мокаем get_current_user dependency
        non_existent_jti = str(uuid.uuid4())
        mock_current_user_data = {
            "sub": str(user.uuid_key),
            "jti": str(uuid.uuid4()),
            "email": user.email,
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Настраиваем auth_service для возврата JTI которого нет в БД
        mock_auth_service.verify_token.return_value = {
            "jti": non_existent_jti,
            "sub": str(user.uuid_key),
            "type": "refresh"
        }
        mock_auth_service.blacklist_token.return_value = None

        payload = {"refresh_token": "some-refresh-token"}

        try:
            response = await client.post("/v1/logout", json=payload)
            assert response.status_code == 401
            assert "Invalid refresh token" in response.json()["detail"]
        finally:
            get_app.dependency_overrides.clear()

    async def test_logout_session_not_found(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        """Тест logout когда сессия не найдена"""
        # Создаем пользователя
        user = UserFactory.build()
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем refresh token БЕЗ связанной сессии
        refresh_token = RefreshTokenFactory.build(
            user_id=user.id,
            jti=str(uuid.uuid4()),
            is_active=True
        )
        session.add(refresh_token)
        await session.commit()
        await session.refresh(refresh_token)

        # Мокаем get_current_user dependency
        mock_current_user_data = {
            "sub": str(user.uuid_key),
            "jti": str(uuid.uuid4()),
            "email": user.email,
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Настраиваем auth_service
        mock_auth_service.verify_token.return_value = {
            "jti": refresh_token.jti,
            "sub": str(user.uuid_key),
            "type": "refresh"
        }
        mock_auth_service.blacklist_token.return_value = None

        payload = {"refresh_token": "mock-refresh-token"}

        try:
            response = await client.post("/v1/logout", json=payload)
            assert response.status_code == 401
            assert "Invalid refresh token" in response.json()["detail"]
        finally:
            get_app.dependency_overrides.clear()

    async def test_logout_user_not_found(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        """Тест logout когда пользователь не найден"""
        # Создаем refresh token с несуществующим user_id
        refresh_token = RefreshTokenFactory.build(
            user_id=999999,  # Несуществующий user_id
            jti=str(uuid.uuid4()),
            is_active=True
        )
        session.add(refresh_token)
        await session.commit()
        await session.refresh(refresh_token)

        # Создаем сессию с несуществующим UUID пользователя
        non_existent_uuid = str(uuid.uuid4())
        user_session = UserSessionFactory.build(
            user_id=non_existent_uuid,
            refresh_token_id=refresh_token.id,
            is_active=True
        )
        session.add(user_session)
        await session.commit()
        await session.refresh(user_session)

        # Мокаем get_current_user dependency
        mock_current_user_data = {
            "sub": non_existent_uuid,
            "jti": str(uuid.uuid4()),
            "email": "test@example.com",
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Настраиваем auth_service
        mock_auth_service.verify_token.return_value = {
            "jti": refresh_token.jti,
            "sub": non_existent_uuid,
            "type": "refresh"
        }
        mock_auth_service.blacklist_token.return_value = None

        payload = {"refresh_token": "mock-refresh-token"}

        try:
            response = await client.post("/v1/logout", json=payload)
            assert response.status_code == 401
            assert "Invalid refresh token" in response.json()["detail"]
        finally:
            get_app.dependency_overrides.clear()

    async def test_logout_with_expired_refresh_token(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        """Тест logout с истекшим refresh token"""
        # Создаем пользователя
        user = UserFactory.build()
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем истекший refresh token
        expired_time = datetime.now(UTC) - timedelta(days=1)
        refresh_token = RefreshTokenFactory.build(
            user_id=user.id,
            jti=str(uuid.uuid4()),
            expires_at=expired_time,
            is_active=False
        )
        session.add(refresh_token)
        await session.commit()
        await session.refresh(refresh_token)

        # Создаем сессию
        user_session = UserSessionFactory.build(
            user_id=str(user.uuid_key),
            refresh_token_id=refresh_token.id,
            is_active=True
        )
        session.add(user_session)
        await session.commit()
        await session.refresh(user_session)

        # Мокаем get_current_user dependency
        mock_current_user_data = {
            "sub": str(user.uuid_key),
            "jti": str(uuid.uuid4()),
            "email": user.email,
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Настраиваем auth_service
        mock_auth_service.verify_token.return_value = {
            "jti": refresh_token.jti,
            "sub": str(user.uuid_key),
            "type": "refresh"
        }
        mock_auth_service.blacklist_token.return_value = None

        payload = {"refresh_token": "mock-refresh-token"}

        try:
            response = await client.post("/v1/logout", json=payload)
            # Даже с истекшим токеном logout должен работать
            assert response.status_code == 200
            assert response.json() == {"message": "Successfully logged out"}
        finally:
            get_app.dependency_overrides.clear()

    async def test_logout_with_already_terminated_session(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        """Тест logout с уже завершенной сессией"""
        # Создаем пользователя
        user = UserFactory.build()
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем refresh token
        refresh_token = RefreshTokenFactory.build(
            user_id=user.id,
            jti=str(uuid.uuid4()),
            is_active=True
        )
        session.add(refresh_token)
        await session.commit()
        await session.refresh(refresh_token)

        # Создаем уже завершенную сессию
        user_session = UserSessionFactory.build(
            user_id=str(user.uuid_key),
            refresh_token_id=refresh_token.id,
            is_active=False,
            terminated_at=datetime.now(UTC)
        )
        session.add(user_session)
        await session.commit()
        await session.refresh(user_session)

        mock_current_user_data = {
            "sub": str(user.uuid_key),
            "jti": str(uuid.uuid4()),
            "email": user.email,
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Настраиваем auth_service
        mock_auth_service.verify_token.return_value = {
            "jti": refresh_token.jti,
            "sub": str(user.uuid_key),
            "type": "refresh"
        }
        mock_auth_service.blacklist_token.return_value = None

        payload = {"refresh_token": "mock-refresh-token"}

        try:
            response = await client.post("/v1/logout", json=payload)
            # Logout должен работать даже с завершенной сессией
            assert response.status_code == 200
            assert response.json() == {"message": "Successfully logged out"}
        finally:
            get_app.dependency_overrides.clear()

    async def test_logout_without_refresh_token_in_body(
            self,
            client: AsyncClient,
            get_app
    ):
        """Тест logout без refresh token в теле запроса"""
        # Мокаем get_current_user dependency
        mock_current_user_data = {
            "sub": str(uuid.uuid4()),
            "jti": str(uuid.uuid4()),
            "email": "test@example.com",
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        try:
            response = await client.post("/v1/logout", json={})
            assert response.status_code == 422  # Validation error
        finally:
            get_app.dependency_overrides.clear()

    async def test_logout_with_multiple_active_sessions(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        """Тест logout когда у пользователя несколько активных сессий"""
        # Создаем пользователя
        user = UserFactory.build()
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем несколько refresh tokens
        refresh_tokens = []
        for i in range(3):
            token = RefreshTokenFactory.build(
                user_id=user.id,
                jti=str(uuid.uuid4()),
                is_active=True
            )
            refresh_tokens.append(token)
            session.add(token)

        await session.commit()
        for token in refresh_tokens:
            await session.refresh(token)

        # Создаем несколько активных сессий
        sessions = []
        for token in refresh_tokens:
            user_session = UserSessionFactory.build(
                user_id=str(user.uuid_key),
                refresh_token_id=token.id,
                is_active=True
            )
            sessions.append(user_session)
            session.add(user_session)

        await session.commit()
        for sess in sessions:
            await session.refresh(sess)

        # Настраиваем моки для logout первой сессии
        target_token = refresh_tokens[0]
        target_session = sessions[0]

        # Мокаем get_current_user dependency
        mock_current_user_data = {
            "sub": str(user.uuid_key),
            "jti": str(uuid.uuid4()),
            "email": user.email,
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Настраиваем auth_service
        mock_auth_service.verify_token.return_value = {
            "jti": target_token.jti,
            "sub": str(user.uuid_key),
            "type": "refresh"
        }
        mock_auth_service.blacklist_token.return_value = None

        payload = {"refresh_token": "mock-refresh-token"}

        try:
            response = await client.post("/v1/logout", json=payload)
            assert response.status_code == 200

            # Проверяем, что только целевая сессия была деактивирована
            await session.refresh(target_session)
            assert target_session.is_active is False
            assert target_session.terminated_at is not None

            # Проверяем, что остальные сессии остались активными
            for other_session in sessions[1:]:
                await session.refresh(other_session)
                assert other_session.is_active is True
                assert other_session.terminated_at is None
        finally:
            get_app.dependency_overrides.clear()


    async def test_logout_auth_service_blacklist_failure(
            self,
            client: AsyncClient,
            session: AsyncSession,
            mock_auth_service,
            get_app
    ):
        """Тест logout при ошибке blacklist в auth_service"""
        # Создаем пользователя
        user = UserFactory.build()
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Создаем refresh-токен
        refresh_token = RefreshTokenFactory.build(user_id=user.id)
        session.add(refresh_token)
        await session.commit()
        await session.refresh(refresh_token)

        # Создаем сессию пользователя
        user_session = UserSessionFactory.build(
            user_id=str(user.uuid_key),
            refresh_token_id=refresh_token.id
        )
        session.add(user_session)
        await session.commit()
        await session.refresh(user_session)

        # Мокаем get_current_user dependency
        mock_current_user_data = {
            "sub": str(user.uuid_key),
            "jti": "mock-access-jti",
            "email": user.email,
            "type": "access"
        }
        get_app.dependency_overrides[get_current_user] = lambda: mock_current_user_data

        # Настраиваем auth_service
        mock_auth_service.verify_token.return_value = {
            "sub": str(user.uuid_key),
            "jti": refresh_token.jti,
            "type": "refresh",
            "token_family": refresh_token.token_family
        }
        # Симулируем ошибку при blacklist
        mock_auth_service.blacklist_token.side_effect = Exception("Blacklist failed")

        payload = {"refresh_token": "mock-refresh-token"}

        try:
            response = await client.post("/v1/logout", json=payload)
            # Должна быть ошибка сервера
            assert response.status_code == 500
        finally:
            get_app.dependency_overrides.clear()