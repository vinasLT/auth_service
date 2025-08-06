from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database.crud.base import BaseService
from database.models import UserSession
from database.schemas.user_session import UserSessionCreate, UserSessionUpdate


class UserSessionService(BaseService[UserSession, UserSessionCreate, UserSessionUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(UserSession, session)

    async def get_session_by_refresh_token_id(self, token_id: int):
        stmt = select(UserSession).where(UserSession.refresh_token_id == token_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()
