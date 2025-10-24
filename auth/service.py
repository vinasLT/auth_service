from enum import Enum

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
from config import settings
from core.logger import logger
from database.models import User

class TokenType(str, Enum):
    REFRESH = "refresh"
    ACCESS = "access"


class AuthService(Signer):
    def __init__(self, session: Session, redis_client: Redis, key_arn: str, signing_algorithm: str = None,
                 cache_ttl: int = 3600, issuer: str = settings.APP_NAME, audience: str = settings.AUDIENCE):
        super().__init__(session, redis_client, key_arn, signing_algorithm, cache_ttl)
        self.issuer = issuer
        self.audience = audience

        self.access_token_ttl = int(timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds())
        self.refresh_token_ttl = int(timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())

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
        return token


    async def generate_token(self, payload: Dict[str, Any]) -> str:
        return await self._encode_and_sign(payload)


    async def get_payload_for_token(self, token_type: TokenType, user: User,
                                    roles_permissions: Dict[str, list[str]] = None,
                                    token_family:str = None) -> Dict[str, Any]:
        if token_type == TokenType.ACCESS:
            ttl_seconds = self.access_token_ttl
        elif token_type == TokenType.REFRESH:
            ttl_seconds = self.refresh_token_ttl
        else:
            raise ValueError("Invalid token type")

        now = datetime.now(timezone.utc)
        payload: Dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": user.uuid_key,
            "email": user.email,
            'phone_number': user.phone_number,
            'email_verified': user.email_verified,
            'phone_verified': user.phone_verified,
            'first_name': user.first_name,
            'last_name': user.last_name,
            "iat": now,
            "exp": now + timedelta(seconds=ttl_seconds),
            "jti": str(uuid.uuid4()),
            "type": token_type,
        }


        if token_type == TokenType.REFRESH.value:
            if not token_family:
                token_family = str(uuid.uuid4())
            payload.update({'token_family': token_family})
        else:
            if roles_permissions:
                payload.update(roles_permissions)
            else:
                raise ValueError("Missing roles_permissions for access token")

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
            logger.exception("Token has expired")
            raise UnauthorisedProblem(detail="Token has expired")
        except jwt.InvalidTokenError as e:
            logger.exception("Invalid token")
            raise UnauthorisedProblem(detail=f"Invalid token: {str(e)}")


    async def is_token_blacklisted(
            self,
            token_type: TokenType,
            jti: str
    ) -> bool:
        redis_key = f"blacklist:{token_type.value}:{jti}"
        return await self.redis_client.exists(redis_key)

    async def blacklist_token(self, token_type: TokenType, jti: str) -> None:
        key = f"blacklist:{token_type.value}:{jti}"
        await self.redis_client.set(key, "blacklisted")

        ttl = self.refresh_token_ttl if token_type == TokenType.REFRESH else self.access_token_ttl
        await self.redis_client.expire(key, ttl)
