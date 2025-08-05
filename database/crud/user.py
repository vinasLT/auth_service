from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.crud.base import BaseService
from database.models import UserRole, Role
from database.models.user import User
from database.schemas.user import UserCreate, UserUpdate




class UserService(BaseService[User, UserCreate, UserUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(User, session)

    async def get_by_email(self, email: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_user_by_uuid(self, uuid: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.uuid_key == uuid)
        )
        return result.scalar_one_or_none()
    async def get_user_with_permissions(self, email: str) -> Optional[User]:
        result = await self.session.execute(
            select(User)
            .filter(User.email == str(email))
            .options(
                selectinload(User.roles).selectinload(UserRole.role).selectinload(Role.permissions)
            )
        )

        user = result.scalar_one_or_none()
        return user

