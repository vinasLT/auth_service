from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.crud.base import BaseService

from database.models.role import Role
from database.schemas.role import RoleCreate, RoleUpdate


class RoleService(BaseService[Role, RoleCreate, RoleUpdate]):
    DEFAULT_ROLE_NAME = "user"

    def __init__(self, session: AsyncSession):
        super().__init__(Role, session)

    async def get_default_role(self):
        result = await self.session.execute(
            select(Role).where(Role.is_default.is_(True))
        )
        role = result.scalar_one_or_none()
        if role is None:
            role = Role(name=self.DEFAULT_ROLE_NAME, description="Default role", is_default=True)
            self.session.add(role)
            await self.session.commit()
            await self.session.refresh(role)
        return role




