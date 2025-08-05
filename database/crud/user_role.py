from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import UserRole
from database.schemas.user_role import UserRoleUpdate, UserRoleCreate


class UserRoleService(BaseService[UserRole, UserRoleCreate, UserRoleUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(UserRole, session)


