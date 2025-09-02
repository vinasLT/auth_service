import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from config import Permissions
from database.crud.permission import PermissionService
from database.crud.role import RoleService
from database.db.session import get_async_db, AsyncSessionLocal
from database.models.permission import ActionEnum
from database.schemas.permission import PermissionCreate
from database.schemas.role import RoleCreate

USER_ROLE = 'user'
ADMIN_ROLE = 'admin'
DEVELOPER_ROLE = 'developer'

ROLES_PERMISSIONS = {
    USER_ROLE: [Permissions.USERS_READ_OWN, Permissions.USERS_WRITE_OWN],
    ADMIN_ROLE: [Permissions.USERS_READ_ALL, Permissions.USERS_WRITE_ALL,
                 Permissions.ROLES_READ_ALL, Permissions.ROLES_WRITE_ALL],
    DEVELOPER_ROLE: list(Permissions)
}

async def initialize_permissions_roles_seed(db: AsyncSession):
    role_service = RoleService(db)
    permission_service = PermissionService(db)
    if await role_service.get_all():
        return

    for role, permissions in ROLES_PERMISSIONS.items():
        new_role = await role_service.create(RoleCreate(name=role, description=f"Default role"))
        created_permissions = []
        for permission in permissions:
            res = permission.split(':')[0]
            act = permission.split(':')[1] if len(permission.split(':')) > 1 else None
            existing_permission = await permission_service.get_by_resource_and_action(res, act)
            if existing_permission:
                created_permissions.append(existing_permission)
                continue
            new_permission = await permission_service.create(PermissionCreate(name='Default permission',
                                                                              description='Default permission',
                                                                              resource=res,
                                                                              action=ActionEnum(act)))
            created_permissions.append(new_permission)
        new_role.permissions = created_permissions
        await db.commit()
        await db.refresh(new_role)

if __name__ == '__main__':
    db = AsyncSessionLocal()
    asyncio.run(initialize_permissions_roles_seed(db))









