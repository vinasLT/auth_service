from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import UserRole
from database.schemas.many_to_many.user_role import UserRoleCreate, UserRoleUpdate


class UserRoleService(BaseService[UserRole, UserRoleCreate, UserRoleUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(UserRole, session)


