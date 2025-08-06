from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models.many_to_many.role_permission import RolePermission
from database.schemas.many_to_many.role_permission import RolePermissionCreate, RolePermissionUpdate


class RolePermissionService(BaseService[RolePermission, RolePermissionCreate, RolePermissionUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(RolePermission, session)
