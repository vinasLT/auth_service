from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database.crud.base import BaseService
from database.models.singing_key import SingingKey, AlgorithmsEnum
from database.schemas.signing_key import SingingKeyUpdate, SingingKeyCreate


class SigningKeyService(BaseService[SingingKey, SingingKeyCreate, SingingKeyUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(SingingKey, session)
        self.session = session

    async def get_newer_active_key(self) -> SingingKey | None:
        stmt = (
            select(SingingKey)
            .where(SingingKey.is_active.is_(True))
            .order_by(SingingKey.created_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        result =  result.scalar_one_or_none()
        if result:
            return result
        else:
            data = SingingKeyCreate(key_arn=settings.AWS_KMS_KEY_ARN, alg=AlgorithmsEnum.RSASSA_PSS_SHA_256)
            result = await self.create(data)
            return result

