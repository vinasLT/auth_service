from fastapi import APIRouter, Depends, Body, Path, Request
from fastapi_pagination.ext.sqlalchemy import paginate
from rfc9457 import NotFoundProblem
from sqlalchemy.ext.asyncio import AsyncSession

from config import Permissions
from database.crud.permission import PermissionService
from database.crud.role import RoleService
from database.db.session import get_async_db
from database.schemas.permission import PermissionRead, PermissionCreate, PermissionUpdate
from database.schemas.role import RoleReadWithPermissions
from dependencies.security import require_all_permissions
from utils.pagination_page import create_pagination_page

permissions_router = APIRouter(prefix="/permission")

PermissionPage = create_pagination_page(PermissionRead)

@permissions_router.get("", response_model=PermissionPage, description='Get all permissions',
                              dependencies=[Depends(require_all_permissions(Permissions.PERMISSIONS_READ_ALL))])
async def get_all_permissions(db: AsyncSession = Depends(get_async_db)):
    permission_service = PermissionService(db)
    stmt = await permission_service.get_all(get_stmt=True)
    return await paginate(db, stmt)

@permissions_router.get("/{permission_id}", response_model=PermissionRead, description='Get one permission',
                              dependencies=[Depends(require_all_permissions(Permissions.PERMISSIONS_READ_ALL))])
async def get_one_permission(permission_id: int, db: AsyncSession = Depends(get_async_db)):
    permission_service = PermissionService(db)
    permission = await permission_service.get(permission_id)
    if not permission:
        raise NotFoundProblem(detail="Permission not found")
    return permission

@permissions_router.post("", response_model=PermissionRead, description='Create one permission',
                               dependencies=[Depends(require_all_permissions(Permissions.PERMISSIONS_WRITE_ALL, Permissions.PERMISSIONS_READ_ALL))])
async def create_one_permission(permission: PermissionCreate = Body(...), db: AsyncSession = Depends(get_async_db)):
    permission_service = PermissionService(db)
    new_permission = await permission_service.create(permission)
    return new_permission

@permissions_router.put("/{permission_id}", response_model=PermissionRead, description='Update one permission'
                        , dependencies=[Depends(require_all_permissions(Permissions.PERMISSIONS_WRITE_ALL, Permissions.PERMISSIONS_READ_ALL))])
async def update_one_permission(permission_id: int = Path(...), updated_permission: PermissionUpdate = Body(...), db: AsyncSession = Depends(get_async_db)):
    permission_service = PermissionService(db)
    permission = await permission_service.get(permission_id)
    if not permission:
        raise NotFoundProblem(detail="Permission not found")
    permission = await permission_service.update(permission_id, updated_permission)
    return permission

@permissions_router.delete("/{permission_id}", description='Delete one permission',
                           dependencies=[Depends(require_all_permissions(Permissions.PERMISSIONS_DELETE_ALL))])
async def delete_one_permission(permission_id: int, db: AsyncSession = Depends(get_async_db)):
    permission_service = PermissionService(db)
    permission = await permission_service.get(permission_id)
    if not permission:
        raise NotFoundProblem(detail="Permission not found")
    await permission_service.delete(permission_id)
    return {'success': True}

@permissions_router.api_route("/{permission_id}/role/{role_id}", response_model=RoleReadWithPermissions,
                              methods=["POST", "DELETE"], description='Assign/Unassign permission to/from role',
                              dependencies=[Depends(require_all_permissions(Permissions.PERMISSIONS_WRITE_ALL,
                                                                            Permissions.PERMISSIONS_READ_ALL,
                                                                            Permissions.ROLES_READ_ALL,
                                                                            Permissions.ROLES_WRITE_ALL))])
async def manage_role_permission(request: Request, permission_id: int = Path(..., description='Permission ID'),
                                 role_id: int = Path(..., description='Role ID'),
                                 db: AsyncSession = Depends(get_async_db)):
    permission_service = PermissionService(db)
    role_service = RoleService(db)
    permission = await permission_service.get_with_not_found_exception(permission_id, 'permission')
    role = await role_service.get_with_not_found_exception(role_id, 'role')

    if request.method == "POST":
        role.permissions.append(permission)
    else:
        role.permissions.remove(permission)

    await db.commit()
    await db.refresh(role)
    return role




