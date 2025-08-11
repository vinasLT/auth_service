from typing import Optional, Dict, List

from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.crud.base import BaseService
from database.models import UserRole, Role
from database.models.many_to_many.role_permission import RolePermission
from database.models.user import User
from database.schemas.user import UserCreate, UserUpdate




class UserService(BaseService[User, UserCreate, UserUpdate]):
    def __init__(self, session: AsyncSession):
        super().__init__(User, session)

    async def get_by_email(self, email: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.email.ilike(email))
        )
        return result.scalar_one_or_none()

    async def get_by_phone_number(self, phone_number: str) -> Optional[User]:
        clean_phone = phone_number.lstrip('+')

        result = await self.session.execute(
            select(User).where(
                or_(
                    User.phone_number == clean_phone,
                    User.phone_number == '+' + clean_phone
                )
            )
        )
        return result.scalar_one_or_none()

    async def get_user_by_uuid(self, uuid: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.uuid_key == uuid)
        )
        return result.scalar_one_or_none()

    async def get_user_with_permissions(self, user_id: int) -> Optional[User]:
        result = await self.session.execute(
            select(User)
            .where(User.id == user_id)
            .options(
                selectinload(User.roles)
                .selectinload(UserRole.role)
                .selectinload(Role.role_permissions)
                .selectinload(RolePermission.permission)
            )
        )

        return result.scalar_one_or_none()

    async def extract_roles_and_permissions_from_user(self, user_id: int, user: User = None) -> Dict[str, List[str]]:

        if not user or (hasattr(user, 'roles') and user.roles is None):
            user = await self.get_user_with_permissions(user_id)

        roles = []
        permissions = set()

        if hasattr(user, 'roles') and user.roles:
            for user_role in user.roles:
                roles.append(user_role.role.name)

                for role_permission in user_role.role.role_permissions:
                    permission = role_permission.permission

                    if permission.resource and permission.action:
                        permissions.add(f"{permission.resource}:{permission.action}")
                    else:
                        permissions.add(permission.name)

        return {
            "roles": roles,
            "permissions": sorted(list(permissions))
        }



