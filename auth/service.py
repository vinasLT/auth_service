import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Literal, Optional
import base64
from aioboto3 import Session
from redis import Redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import uuid
import json

from rfc9457 import UnauthorisedProblem

from auth.kms_sign import Signer


class AuthService(Signer):

    def __init__(self, session: Session, redis_client: Redis, key_arn: str, signing_algorithm: str = None,
                 cache_ttl: int = 3600, issuer: str = 'auth-service', audience: str = 'web-api'):
        super().__init__(session, redis_client, key_arn, signing_algorithm, cache_ttl)
        self.issuer = issuer
        self.audience = audience

        self.access_token_ttl = int(timedelta(minutes=15).total_seconds())
        self.refresh_token_ttl = int(timedelta(days=30).total_seconds())


        self._algorithm_mapping = {
            'RSASSA_PSS_SHA_256': 'PS256',
            'RSASSA_PSS_SHA_384': 'PS384',
            'RSASSA_PSS_SHA_512': 'PS512',
            'RSASSA_PKCS1_V1_5_SHA_256': 'RS256',
            'RSASSA_PKCS1_V1_5_SHA_384': 'RS384',
            'RSASSA_PKCS1_V1_5_SHA_512': 'RS512',
            'ECDSA_SHA_256': 'ES256',
            'ECDSA_SHA_384': 'ES384',
            'ECDSA_SHA_512': 'ES512',
        }

    @staticmethod
    def hash_password(password: str) -> str:
        pw_bytes = password.encode("utf-8") if isinstance(password, str) else password
        hashed = bcrypt.hashpw(pw_bytes, bcrypt.gensalt())
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        if not hashed_password:
            return False
        pw_bytes = password.encode("utf-8") if isinstance(password, str) else password
        hp_bytes = hashed_password.encode("utf-8") if isinstance(hashed_password, str) else hashed_password
        try:
            return bcrypt.checkpw(pw_bytes, hp_bytes)
        except ValueError:
            return False

    async def _get_jwt_algorithm(self) -> str:
        if self.signing_algorithm is None:
            info = await self.get_key_info()
            algos = info.get("SigningAlgorithms") or []
            if not algos:
                raise ValueError("No available signing algorithms for the key")
            self.signing_algorithm = algos[0]

        jwt_algo = self._algorithm_mapping.get(self.signing_algorithm)
        if not jwt_algo:
            raise ValueError(f"Unsupported KMS signing algorithm: {self.signing_algorithm}")

        return jwt_algo

    async def _encode_and_sign(self, payload: Dict[str, Any]) -> str:
        jwt_algo = await self._get_jwt_algorithm()
        kid = self.key_arn.split('/')[-1]

        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

        processed_payload = {}
        for k, v in payload.items():
            if isinstance(v, datetime):
                dt = v if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)
                ts = int(dt.astimezone(timezone.utc).timestamp())
                processed_payload[k] = ts
            else:
                processed_payload[k] = v

        header = {"alg": jwt_algo, "typ": "JWT", "kid": kid}

        header_encoded = b64url(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        payload_encoded = b64url(
            json.dumps(processed_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

        message = f"{header_encoded}.{payload_encoded}".encode("ascii")

        signature = await self.sign(message)
        signature_encoded = b64url(signature)

        token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
        print(token)
        return token


    async def generate_token(self, payload: Dict[str, Any]) -> str:
        return await self._encode_and_sign(payload)


    async def get_payload_for_token(self, token_type: Literal["access", "refresh"], user_uuid: str, email: str,
                                    token_family:str = None) -> Dict[str, Any]:
        if token_type == "access":
            ttl_seconds = self.access_token_ttl
        elif token_type == "refresh":
            ttl_seconds = self.refresh_token_ttl
        else:
            raise ValueError("Invalid token type")

        now = datetime.now(timezone.utc)
        payload: Dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": user_uuid,
            "email": email,
            "iat": now,
            "exp": now + timedelta(seconds=ttl_seconds),
            "jti": str(uuid.uuid4()),
            "type": token_type,
        }

        if token_type == 'refresh':
            if not token_family:
                token_family = str(uuid.uuid4())
            payload.update({'token_family': token_family})

        return payload


    async def verify_token(self, token: str) -> Dict[str, Any]:
        try:
            public_key_bytes = await self.get_public_key()

            public_key = serialization.load_der_public_key(
                public_key_bytes,
                backend=default_backend()
            )

            jwt_algo = await self._get_jwt_algorithm()

            payload = jwt.decode(
                token,
                public_key,
                algorithms=[jwt_algo],
                audience=self.audience,
                issuer=self.issuer
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise UnauthorisedProblem(detail="Token has expired")
        except jwt.InvalidTokenError as e:
            raise UnauthorisedProblem(detail=f"Invalid token: {str(e)}")


    async def is_token_blacklisted(
            self,
            token_type: Literal["access", "refresh"],
            jti: str
    ) -> bool:
        redis_key = f"blacklist:{token_type}:{jti}"
        return await self.redis_client.exists(redis_key)

    async def blacklist_token(self, token_type: Literal["access", "refresh"], jti: str) -> None:
        key = f"blacklist:{token_type}:{jti}"
        await self.redis_client.set(key, "blacklisted")

        ttl = self.refresh_token_ttl if token_type == "refresh" else self.access_token_ttl
        await self.redis_client.expire(key, ttl)







    # async def revoke_all_user_tokens(
    #         self,
    #         db: AsyncSession,
    #         user_id: str,
    #         reason: Optional[str] = None,
    #         revoked_by: Optional[str] = None
    # ) -> None:
    #     """Отозвать все токены пользователя"""
    #     # Отзываем все активные refresh токены
    #     await db.execute(
    #         update(RefreshToken)
    #         .where(and_(
    #             RefreshToken.user_id == user_id,
    #             RefreshToken.is_active == True
    #         ))
    #         .values(
    #             is_active=False,
    #             revoked_at=datetime.now(timezone.utc),
    #             revoke_reason=reason or "All user tokens revoked"
    #         )
    #     )
    #
    #     # Завершаем все активные сессии
    #     await db.execute(
    #         update(UserSession)
    #         .where(and_(
    #             UserSession.user_id == user_id,
    #             UserSession.is_active == True
    #         ))
    #         .values(
    #             is_active=False,
    #             terminated_at=datetime.now(timezone.utc),
    #             termination_reason=reason or "All user tokens revoked"
    #         )
    #     )
    #
    #     await db.commit()
    #
    #     # Добавляем пользователя в Redis blacklist на время жизни самого долгого токена
    #     user_blacklist_key = f"blacklist:user:{user_id}"
    #     await self.redis_client.setex(
    #         user_blacklist_key,
    #         self.refresh_token_ttl,
    #         datetime.now(timezone.utc).isoformat()
    #     )

    # async def get_user_active_sessions(
    #         self,
    #         db: AsyncSession,
    #         user_id: str
    # ) -> List[Dict[str, Any]]:
    #     """Получить список активных сессий пользователя"""
    #     result = await db.execute(
    #         select(RefreshToken)
    #         .where(and_(
    #             RefreshToken.user_id == user_id,
    #             RefreshToken.is_active == True,
    #             RefreshToken.expires_at > datetime.now(timezone.utc)
    #         ))
    #         .order_by(RefreshToken.created_at.desc())
    #     )
    #
    #     sessions = []
    #     for token in result.scalars().all():
    #         sessions.append({
    #             "id": token.id,
    #             "device_name": token.device_name,
    #             "device_id": token.device_id,
    #             "ip_address": token.ip_address,
    #             "user_agent": token.user_agent,
    #             "created_at": token.created_at.isoformat(),
    #             "last_used": token.used_at.isoformat() if token.used_at else None,
    #             "expires_at": token.expires_at.isoformat()
    #         })
    #
    #     return sessions

    # async def revoke_user_session(
    #         self,
    #         db: AsyncSession,
    #         user_id: str,
    #         session_id: str,
    #         reason: Optional[str] = None
    # ) -> None:
    #     """Отозвать конкретную сессию пользователя"""
    #     result = await db.execute(
    #         select(RefreshToken)
    #         .where(and_(
    #             RefreshToken.id == session_id,
    #             RefreshToken.user_id == user_id
    #         ))
    #     )
    #     refresh_token = result.scalar_one_or_none()
    #
    #     if not refresh_token:
    #         raise ValueError("Session not found")
    #
    #     # Отзываем всю token family
    #     await self._revoke_token_family(
    #         db,
    #         refresh_token.token_family,
    #         reason or "Session terminated by user"
    #     )

    # async def cleanup_expired_tokens(self, db: AsyncSession) -> int:
    #     """Очистить истекшие токены и записи blacklist"""
    #     now = datetime.now(timezone.utc)
    #
    #     # Удаляем истекшие записи из blacklist
    #     blacklist_result = await db.execute(
    #         delete(TokenBlacklist)
    #         .where(TokenBlacklist.expires_at < now)
    #     )
    #
    #     # Удаляем старые неактивные refresh токены
    #     cutoff_date = now - timedelta(days=30)  # Храним 30 дней для аудита
    #     refresh_result = await db.execute(
    #         delete(RefreshToken)
    #         .where(and_(
    #             RefreshToken.is_active == False,
    #             RefreshToken.expires_at < cutoff_date
    #         ))
    #     )
    #
    #     # Удаляем старые записи истории входов
    #     history_cutoff = now - timedelta(days=90)  # Храним 90 дней
    #     history_result = await db.execute(
    #         delete(LoginHistory)
    #         .where(LoginHistory.login_at < history_cutoff)
    #     )
    #
    #     await db.commit()
    #
    #     total_deleted = (
    #             blacklist_result.rowcount +
    #             refresh_result.rowcount +
    #             history_result.rowcount
    #     )
    #
    #     return total_deleted

    # async def get_user_login_history(
    #         self,
    #         db: AsyncSession,
    #         user_id: str,
    #         limit: int = 10
    # ) -> List[Dict[str, Any]]:
    #     """Получить историю входов пользователя"""
    #     result = await db.execute(
    #         select(LoginHistory)
    #         .where(LoginHistory.user_id == user_id)
    #         .order_by(LoginHistory.login_at.desc())
    #         .limit(limit)
    #     )
    #
    #     history = []
    #     for entry in result.scalars().all():
    #         history.append({
    #             "login_at": entry.login_at.isoformat(),
    #             "success": entry.success,
    #             "ip_address": entry.ip_address,
    #             "user_agent": entry.user_agent,
    #             "auth_method": entry.auth_method,
    #             "failure_reason": entry.failure_reason
    #         })
    #
    #     return history

    # async def create_session(
    #         self,
    #         db: AsyncSession,
    #         user_id: str,
    #         refresh_token_id: str,
    #         expires_at: datetime,
    #         device_info: Optional[str] = None,
    #         ip_address: Optional[str] = None,
    #         location: Optional[str] = None
    # ) -> UserSession:
    #     """Создать новую сессию пользователя"""
    #     session = UserSession(
    #         user_id=user_id,
    #         refresh_token_id=refresh_token_id,
    #         session_key=str(uuid.uuid4()),
    #         expires_at=expires_at,
    #         device_info=device_info,
    #         ip_address=ip_address,
    #         location=location
    #     )
    #
    #     db.add(session)
    #     await db.commit()
    #     await db.refresh(session)
    #
    #     # Кешируем сессию в Redis
    #     session_key = f"session:{session.session_key}"
    #     session_data = {
    #         "user_id": user_id,
    #         "session_id": session.id,
    #         "created_at": session.started_at.isoformat()
    #     }
    #
    #     ttl = int((expires_at - datetime.now(timezone.utc)).total_seconds())
    #     await self.redis_client.setex(
    #         session_key,
    #         ttl,
    #         json.dumps(session_data)
    #     )
    #
    #     return session

    # async def update_session_activity(
    #         self,
    #         db: AsyncSession,
    #         session_key: str
    # ) -> None:
    #     """Обновить время последней активности сессии"""
    #     # Проверяем в Redis
    #     redis_key = f"session:{session_key}"
    #     session_data = await self.redis_client.get(redis_key)
    #
    #     if session_data:
    #         # Обновляем в БД
    #         await db.execute(
    #             update(UserSession)
    #             .where(UserSession.session_key == session_key)
    #             .values(last_activity=datetime.now(timezone.utc))
    #         )
    #         await db.commit()









# class AuthServiceDB(Signer):
#     def __init__(
#             self,
#             session: aioboto3.Session,
#             redis_client: Redis,
#             key_arn: str,
#             issuer: str = "auth-service",
#             audience: str = "api",
#             access_token_ttl: int = 900,  # 15 minutes
#             refresh_token_ttl: int = 604800,  # 7 days
#             signing_algorithm: str = None,
#             cache_ttl: int = 3600
#     ):
#         super().__init__(session, redis_client, key_arn, signing_algorithm, cache_ttl)
#         self.issuer = issuer
#         self.audience = audience
#         self.access_token_ttl = access_token_ttl
#         self.refresh_token_ttl = refresh_token_ttl
#         self._public_key_cache = {}
#
#
#
#
#
#
#
#
#
#     async def create_user(
#             self,
#             db: AsyncSession,
#             email: str,
#             password: str,
#             username: Optional[str] = None,
#             **kwargs
#     ) -> User:
#         """Создать нового пользователя"""
#         user = User(
#             email=email,
#             password_hash=self.hash_password(password),
#             username=username,
#             **kwargs
#         )
#         db.add(user)
#         await db.commit()
#         await db.refresh(user)
#         return user
#
#     async def authenticate_user(
#             self,
#             db: AsyncSession,
#             email: str,
#             password: str,
#             ip_address: Optional[str] = None,
#             user_agent: Optional[str] = None
#     ) -> Optional[User]:
#         """Аутентифицировать пользователя"""
#         # Ищем пользователя
#         result = await db.execute(
#             select(User).where(User.email == email)
#         )
#         user = result.scalar_one_or_none()
#
#         # Создаем запись в истории входов
#         login_history = LoginHistory(
#             user_id=user.id if user else None,
#             success=False,
#             ip_address=ip_address,
#             user_agent=user_agent,
#             auth_method="password"
#         )
#
#         if not user:
#             login_history.failure_reason = "User not found"
#             db.add(login_history)
#             await db.commit()
#             return None
#
#         if not self.verify_password(password, user.password_hash):
#             login_history.failure_reason = "Invalid password"
#             db.add(login_history)
#             await db.commit()
#             return None
#
#         if not user.is_active:
#             login_history.failure_reason = "User inactive"
#             db.add(login_history)
#             await db.commit()
#             return None
#
#         # Успешный вход
#         login_history.success = True
#         user.last_login_at = datetime.now(timezone.utc)
#
#         db.add(login_history)
#         await db.commit()
#         await db.refresh(user)
#
#         return user
#
#
#
#
#
#     async def refresh_tokens(
#             self,
#             db: AsyncSession,
#             refresh_token: str,
#             client_id: Optional[str] = None,
#             device_id: Optional[str] = None,
#             device_name: Optional[str] = None,
#             user_agent: Optional[str] = None,
#             ip_address: Optional[str] = None
#     ) -> Tuple[str, str, RefreshToken]:
#         """Обновить токены используя refresh token"""
#         # Верифицируем refresh token
#         payload = await self.verify_token(refresh_token)
#
#         if payload.get("type") != "refresh":
#             raise ValueError("Invalid token type")
#
#         jti = payload.get("jti")
#         token_family = payload.get("token_family")
#         user_id = payload.get("sub")
#         email = payload.get("email")
#
#         # Проверяем токен в БД
#         result = await db.execute(
#             select(RefreshToken)
#             .where(RefreshToken.jti == jti)
#             .options(selectinload(RefreshToken.user))
#         )
#         refresh_token_db = result.scalar_one_or_none()
#
#         if not refresh_token_db:
#             # Токен не найден, возможно уже использован
#             # Блокируем всю token family
#             await self._revoke_token_family(db, token_family, "Token reuse detected")
#             raise ValueError("Refresh token not found or already used")
#
#         if not refresh_token_db.is_active:
#             # Токен уже отозван
#             await self._revoke_token_family(db, token_family, "Attempted to use revoked token")
#             raise ValueError("Token has been revoked")
#
#         if refresh_token_db.used_at:
#             # Токен уже был использован - это попытка повторного использования
#             await self._revoke_token_family(db, token_family, "Token reuse detected")
#             raise ValueError("Token has already been used")
#
#         # Проверяем, активен ли пользователь
#         if not refresh_token_db.user.is_active:
#             raise ValueError("User account is inactive")
#
#         # Помечаем старый токен как использованный
#         refresh_token_db.used_at = datetime.now(timezone.utc)
#         refresh_token_db.is_active = False
#
#         # Создаем новые токены
#         access_token = await self.create_access_token(user_id, email)
#
#         new_refresh_token, new_refresh_token_db = await self.create_refresh_token(
#             db=db,
#             user_id=user_id,
#             email=email,
#             client_id=client_id or refresh_token_db.client_id,
#             device_id=device_id or refresh_token_db.device_id,
#             device_name=device_name or refresh_token_db.device_name,
#             user_agent=user_agent or refresh_token_db.user_agent,
#             ip_address=ip_address or refresh_token_db.ip_address,
#             token_family=token_family
#         )
#
#         # Связываем старый и новый токены
#         refresh_token_db.replaced_by_id = new_refresh_token_db.id
#
#         await db.commit()
#
#         return access_token, new_refresh_token, new_refresh_token_db
#
#     async def _revoke_token_family(
#             self,
#             db: AsyncSession,
#             token_family: str,
#             reason: str
#     ) -> None:
#         """Отозвать всю token family"""
#         await db.execute(
#             update(RefreshToken)
#             .where(and_(
#                 RefreshToken.token_family == token_family,
#                 RefreshToken.is_active == True
#             ))
#             .values(
#                 is_active=False,
#                 revoked_at=datetime.now(timezone.utc),
#                 revoke_reason=reason
#             )
#         )
#         await db.commit()
#
#     async def revoke_refresh_token(
#             self,
#             db: AsyncSession,
#             jti: str,
#             reason: Optional[str] = None,
#             revoked_by: Optional[str] = None
#     ) -> None:
#         """Отозвать конкретный refresh token"""
#         result = await db.execute(
#             select(RefreshToken).where(RefreshToken.jti == jti)
#         )
#         refresh_token = result.scalar_one_or_none()
#
#         if refresh_token and refresh_token.is_active:
#             refresh_token.is_active = False
#             refresh_token.revoked_at = datetime.now(timezone.utc)
#             refresh_token.revoke_reason = reason
#             await db.commit()

    # async def blacklist_access_token(
    #         self,
    #         db: AsyncSession,
    #         jti: str,
    #         user_id: str,
    #         expires_at: datetime,
    #         reason: Optional[str] = None,
    #         revoked_by: Optional[str] = None,
    #         ip_address: Optional[str] = None
    # ) -> None:
    #     """Добавить access token в blacklist"""
    #     blacklist_entry = TokenBlacklist(
    #         jti=jti,
    #         token_type="access",
    #         user_id=user_id,
    #         expires_at=expires_at,
    #         reason=reason,
    #         revoked_by=revoked_by,
    #         ip_address=ip_address
    #     )
    #     db.add(blacklist_entry)
    #     await db.commit()