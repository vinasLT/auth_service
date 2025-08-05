from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models.login_history import LoginHistory
from database.schemas.login_history import LoginHistoryCreate, LoginHistoryUpdate


class LoginHistoryService(BaseService[LoginHistory, LoginHistoryCreate, LoginHistoryUpdate]):

    def __init__(self, session: AsyncSession):
        super().__init__(LoginHistory, session)