from datetime import datetime, UTC
from typing import Optional

from rfc9457 import UnauthorisedProblem
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models.refresh_token import RefreshToken
from database.schemas.refresh_token import RefreshTokenCreate, RefreshTokenUpdate


class RefreshTokenService(BaseService[RefreshToken, RefreshTokenCreate, RefreshTokenUpdate]):

    def __init__(self, session: AsyncSession):
        super().__init__(RefreshToken, session)

    async def get_by_jti(self, jti: str) -> Optional[RefreshToken]:
        stmt = select(RefreshToken).where(RefreshToken.jti == jti)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_last_token_in_family(self, family_id: str, only_active: bool = True, require_not_expired: bool = True) -> Optional[RefreshToken]:
        now = datetime.now(UTC)
        conditions = [RefreshToken.token_family == family_id, RefreshToken.replaced_by_id.is_(None)]
        if only_active:
            conditions.append(RefreshToken.is_active.is_(True))
            conditions.append(RefreshToken.revoked_at.is_(None))
        if require_not_expired:
            conditions.append(RefreshToken.expires_at > now)
        stmt = select(RefreshToken).where(and_(*conditions)).limit(1)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def rotate_refresh(self, *, current_jti: str, new_jti: str, new_expires_at: datetime) -> RefreshToken:
        now = datetime.now(UTC)
        stmt = select(RefreshToken).where(RefreshToken.jti == current_jti).limit(1).with_for_update()
        res = await self.session.execute(stmt)
        current = res.scalar_one_or_none()

        if current is None:
            raise UnauthorisedProblem("refresh not found")
        if not current.is_active or current.revoked_at is not None:
            raise UnauthorisedProblem("refresh not active")
        if current.used_at is not None or current.replaced_by_id is not None:
            raise UnauthorisedProblem("refresh already used")

        expires_at = current.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        if expires_at <= now:
            raise UnauthorisedProblem("refresh expired")

        if new_expires_at.tzinfo is None:
            new_expires_at = new_expires_at.replace(tzinfo=UTC)

        new_token = RefreshToken(
            jti=new_jti,
            user_id=current.user_id,
            token_family=current.token_family,
            issued_at=now,
            expires_at=new_expires_at,
            device_name=current.device_name,
            user_agent=current.user_agent,
            ip_address=current.ip_address,
            is_active=True,
        )
        self.session.add(new_token)
        await self.session.flush()

        current.used_at = now
        current.is_active = False
        current.replaced_by_id = new_token.id
        await self.session.flush()

        await self.session.commit()

        return new_token

    async def revoke_family(self, family_id: str) -> int:
        now = datetime.now(UTC)
        stmt = select(RefreshToken).where(RefreshToken.token_family == family_id, RefreshToken.is_active.is_(True))
        res = await self.session.execute(stmt)
        tokens = res.scalars().all()
        for t in tokens:
            t.is_active = False
            t.revoked_at = now
        await self.session.flush()
        await self.session.commit()
        return len(tokens)

    async def detect_reuse(self, jti: str) -> Optional[RefreshToken]:
        stmt = select(RefreshToken).where(RefreshToken.jti == jti).limit(1)
        res = await self.session.execute(stmt)
        token = res.scalar_one_or_none()
        if token is None:
            return None
        if token.used_at is not None or token.replaced_by_id is not None or not token.is_active:
            return token
        return None
