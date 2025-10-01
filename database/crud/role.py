from rfc9457 import BadRequestProblem, NotFoundProblem
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.logger import logger
from database.crud.base import BaseService
from database.models import Permission

from database.models.role import Role
from database.schemas.role import RoleCreate, RoleUpdate
from schemas.request_schemas.role import CreateRoleIn, UpdateRoleIn


class RoleService(BaseService[Role, RoleCreate, RoleUpdate]):


    def __init__(self, session: AsyncSession):
        super().__init__(Role, session)

    async def get_default_role(self):
        result = await self.session.execute(
            select(Role).where(Role.name == 'user')
        )
        role = result.scalar_one_or_none()

        if role is None:
            role = Role(name='user', description="Default role", is_default=True)
            self.session.add(role)
            await self.session.commit()
            await self.session.refresh(role)
            return role
        if not role.is_default:
            role.is_default = True
            await self.session.commit()
            await self.session.refresh(role)
        return role

    async def create_with_permissions(self, role_data: CreateRoleIn) -> Role | list[int]:
        role_create = RoleCreate(
            name=role_data.name,
            description=role_data.description
        )
        new_role = await self.create(role_create)

        if role_data.permission_ids:

            result = await self.session.execute(
                select(Permission).where(Permission.id.in_(role_data.permission_ids))
            )
            permissions = result.scalars().all()

            if len(permissions) != len(role_data.permission_ids):
                found_ids = {p.id for p in permissions}
                missing_ids = set(role_data.permission_ids) - found_ids

                await self.session.rollback()
                logger.warning(f'Permission ids missed while crating new role', extra={
                    "missing_ids": missing_ids
                })
                raise BadRequestProblem(f'Permission ids missed {missing_ids}')

            new_role.permissions.extend(permissions)

            await self.session.commit()
            await self.session.refresh(new_role)

        return new_role

    async def update_with_permissions(self, role_id: int, role_data: UpdateRoleIn) -> Role:
        result = await self.session.execute(
            select(Role).where(Role.id == role_id)
        )
        role = result.scalar_one_or_none()

        if not role:
            raise NotFoundProblem(f'Role with id {role_id} not found')

        if role_data.name is not None:
            role.name = role_data.name
        if role_data.description is not None:
            role.description = role_data.description

        if role_data.permission_ids is not None:
            if role_data.permission_ids:
                result = await self.session.execute(
                    select(Permission).where(Permission.id.in_(role_data.permission_ids))
                )
                permissions = result.scalars().all()

                if len(permissions) != len(role_data.permission_ids):
                    found_ids = {p.id for p in permissions}
                    missing_ids = set(role_data.permission_ids) - found_ids

                    await self.session.rollback()
                    logger.warning(f'Permission ids missed while updating role', extra={
                        "missing_ids": missing_ids,
                        "role_id": role_id
                    })
                    raise BadRequestProblem(f'Permission ids missed {missing_ids}')

                role.permissions.clear()
                role.permissions.extend(permissions)
            else:
                role.permissions.clear()

        await self.session.commit()
        await self.session.refresh(role)

        return role





