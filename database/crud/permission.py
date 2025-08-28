from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import Permission

from database.schemas.permission import PermissionCreate, PermissionUpdate


class PermissionService(BaseService[Permission, PermissionCreate, PermissionUpdate]):
    def __init__(self, db: AsyncSession):
        super().__init__(Permission, db)




