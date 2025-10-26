from typing import Optional, Sequence

from sqlalchemy import select, and_, Select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService
from database.models import Permission

from database.schemas.permission import PermissionCreate, PermissionUpdate


class PermissionService(BaseService[Permission, PermissionCreate, PermissionUpdate]):
    def __init__(self, db: AsyncSession):
        super().__init__(Permission, db)


    async def get_by_resource_and_action(self, resource: str, action: str)-> Optional[Permission]:
        stmt = select(Permission).where(and_(Permission.resource == resource, Permission.action == action))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_all_with_search(self, search: str | None, get_stmt: bool = False)-> Select[tuple[Permission]] | Sequence[Permission]:
        stmt = select(Permission).where(or_(Permission.name.icontains(search), Permission.description.icontains(search)))
        if get_stmt:
            return stmt
        result = await self.session.execute(stmt)
        return result.scalars().all()




