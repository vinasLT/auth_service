from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import UserSession
from database.schemas.user_session import UserSessionCreate, UserSessionUpdate


class UserSessionService(BaseService[UserSession, UserSessionCreate, UserSessionUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(UserSession, session)
