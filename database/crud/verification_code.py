import uuid
from datetime import datetime, UTC, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from database.crud.base import BaseService
from database.models.verification_code import VerificationCode, Destination
from database.schemas.verification_code import VerificationCodeCreate, VerificationCodeUpdate


class VerificationCodeService(BaseService[VerificationCode, VerificationCodeCreate, VerificationCodeUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(VerificationCode, session)

    async def deactivate_all_codes(self, user_id: int, destination: Destination) -> int:
        stmt = (
            update(VerificationCode)
            .where(
                VerificationCode.user_id == user_id,
                VerificationCode.destination == destination,
                VerificationCode.is_verified == False
            )
            .values(is_verified=True)
        )

        result = await self.session.execute(stmt)
        return result.rowcount

    async def verify_code(self, user_id: int, code: str, destination: Destination) -> bool:
        now = datetime.now(UTC)

        stmt = (
            update(VerificationCode)
            .where(
                VerificationCode.user_id == user_id,
                VerificationCode.code == code,
                VerificationCode.destination == destination,
                VerificationCode.is_verified == False,
                VerificationCode.expires_at > now
            )
            .values(
                is_verified=True,
                verified_at=now
            )
            .execution_options(synchronize_session=False)
        )

        result = await self.session.execute(stmt)
        return result.rowcount == 1

    async def create_code_with_deactivation(self, user_id: int, code: str, destination: Destination,
                                            expires_in_minutes: int = 10) -> VerificationCode:
        await self.deactivate_all_codes(user_id, destination)

        now = datetime.now(UTC)
        verification_data = VerificationCodeCreate(
            uuid_key=str(uuid.uuid4()),
            user_id=user_id,
            code=code,
            destination=destination,
            expires_at=now + timedelta(minutes=expires_in_minutes),
            created_at=now
        )

        return await self.create(verification_data)

    async def can_send_new_code(self, user_id: int, destination: Destination, cooldown_seconds: int = 60) -> bool:
        now = datetime.now(UTC)
        cooldown_time = now - timedelta(seconds=cooldown_seconds)

        stmt = (
            select(VerificationCode)
            .where(
                VerificationCode.user_id == user_id,
                VerificationCode.destination == destination,
                VerificationCode.created_at > cooldown_time
            )
        )

        result = await self.session.execute(stmt)
        recent_code = result.scalars().first()

        return recent_code is None

