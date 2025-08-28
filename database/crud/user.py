from typing import Optional, Dict, List, Union, Any, Coroutine, Sequence

from sqlalchemy import select, func, or_, Select, and_, GenerativeSelect, Row, RowMapping
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

    async def get_by_email(self, email: str, is_verified: bool = True) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.email.ilike(email), User.email_verified.is_(is_verified))
        )
        return result.scalar_one_or_none()

    async def get_by_phone_number(self, phone_number: str, is_verified: bool = True) -> Optional[User]:
        clean_phone = phone_number.lstrip('+')

        result = await self.session.execute(
            select(User).where(
                or_(
                    User.phone_number == clean_phone,
                    User.phone_number == '+' + clean_phone
                ),
                User.phone_verified.is_(is_verified)
            )
        )
        return result.scalar_one_or_none()

    async def get_all_users(
            self,
            search: str = '',
            get_stmt: bool = False,
            include_inactive: bool = False,
    ) -> Select[tuple[User]] | Sequence[User]:
        query = await self.get_all(get_stmt=True)

        conditions = []

        if not include_inactive:
            conditions.append(User.is_active == True)

        if search.strip():
            search_term = f"%{search.lower()}%"
            search_conditions = [
                func.lower(User.email).like(search_term),
                func.lower(User.username).like(search_term),
                func.lower(User.first_name).like(search_term),
                func.lower(User.last_name).like(search_term),
                func.lower(User.phone_number).like(search_term),
                func.lower(func.concat(User.first_name, ' ', User.last_name)).like(search_term)
            ]
            conditions.append(or_(*search_conditions))

        if conditions:
            query = query.where(and_(*conditions))

        query = query.order_by(User.created_at.desc())

        if get_stmt:
            return query

        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_user_by_uuid(self, uuid: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.uuid_key == uuid)
        )
        return result.scalar_one_or_none()


    async def extract_roles_and_permissions_from_user(self, user_id: int, user: User = None) -> Dict[str, List[str]]:

        if not user or (hasattr(user, 'roles') and user.roles is None):
            user = await self.get(user_id)

        roles = []
        permissions = set()

        if hasattr(user, 'roles') and user.roles:
            for role in user.roles:
                roles.append(role.name)

                for permission in role.permissions:

                    if permission.resource and permission.action:
                        permissions.add(f"{permission.resource}:{permission.action}")
                    else:
                        permissions.add(permission.name)

        return {
            "roles": roles,
            "permissions": sorted(list(permissions))
        }



