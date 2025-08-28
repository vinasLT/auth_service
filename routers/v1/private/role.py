from fastapi import APIRouter, Depends, Path, Body
from fastapi_pagination.ext.sqlalchemy import paginate
from rfc9457 import NotFoundProblem
from sqlalchemy.ext.asyncio import AsyncSession

from auth.service import AuthService
from config import Permissions
from database.crud.role import RoleService
from database.crud.user import UserService
from database.db.session import get_async_db
from database.schemas.role import RoleReadWithPermissions
from dependencies.security import require_all_permissions
from deps import get_auth_service
from schemas.request_schemas.role import CreateRoleIn, UpdateRoleIn
from schemas.response_schemas.role import AssignRoleToUserIn
from schemas.response_schemas.users import FullUserOut
from utils import create_pagination_page

roles_router = APIRouter( prefix='/role')

RolePage = create_pagination_page(RoleReadWithPermissions)


@roles_router.get("", response_model=RolePage, description='Get all roles',
                              dependencies=[Depends(require_all_permissions(Permissions.ROLES_READ_ALL))])
async def get_all_roles(db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    stmt = await role_service.get_all(get_stmt=True)
    return await paginate(db, stmt)


@roles_router.get("/{role_id}", response_model=RoleReadWithPermissions, description='Get one role',
                              dependencies=[Depends(require_all_permissions(Permissions.ROLES_READ_ALL))])
async def get_one_role(role_id: int, db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    role = await role_service.get(role_id)
    if not role:
        raise NotFoundProblem(detail="Role not found")
    return role

@roles_router.post("", response_model=RoleReadWithPermissions, description='Create one role',
                   dependencies=[Depends(require_all_permissions(Permissions.ROLES_READ_ALL,
                                                                 Permissions.ROLES_WRITE_ALL))])
async def create_one_role(role: CreateRoleIn = Body(...), db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    new_role = await role_service.create_with_permissions(role)
    return new_role

@roles_router.put("/{role_id}", response_model=RoleReadWithPermissions, description='Update one role',
                  dependencies=[Depends(require_all_permissions(Permissions.ROLES_WRITE_ALL,
                                                                Permissions.ROLES_READ_ALL))])
async def update_one_role(role_id: int = Path(...), updated_role: UpdateRoleIn = Body(...), db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    role = await role_service.update_with_permissions(role_id, updated_role)
    return role


@roles_router.delete("/{role_id}", description='Delete one role',
                     dependencies=[Depends(require_all_permissions(Permissions.ROLES_DELETE_ALL))])
async def delete_one_role(role_id: int, db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    role = await role_service.get(role_id)
    if not role:
        raise NotFoundProblem(detail="Role not found")
    await role_service.delete(role_id)
    return {'success': True}

@roles_router.post("/assign-role-to-user", response_model=FullUserOut, description='Assign role to user',
                   dependencies=[Depends(require_all_permissions(Permissions.ROLES_WRITE_ALL,
                                                                Permissions.ROLES_READ_ALL, Permissions.USERS_WRITE_ALL,
                                                                 Permissions.USERS_READ_ALL))])
async def assign_role_to_user(data: AssignRoleToUserIn = Body(...), db: AsyncSession = Depends(get_async_db),
                              auth_service: AuthService = Depends(get_auth_service)):
    role_service = RoleService(db)
    user_service = UserService(db)
    user = await user_service.get_user_by_uuid(data.user_uuid)
    if not user:
        raise NotFoundProblem(detail="User not found")
    role = await role_service.get(data.role_id)
    if not role:
        raise NotFoundProblem(detail="Role not found")

    user.roles.append(role)
    await db.commit()
    await db.refresh(user)
    return user




