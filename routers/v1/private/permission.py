from fastapi import APIRouter, Depends
from fastapi_pagination.ext.sqlalchemy import paginate
from rfc9457 import NotFoundProblem
from sqlalchemy.ext.asyncio import AsyncSession

from config import Permissions
from database.crud.permission import PermissionService
from database.crud.role import RoleService
from database.db.session import get_async_db
from database.schemas.permission import PermissionRead
from database.schemas.role import RoleReadWithPermissions
from dependencies.security import require_all_permissions
from utils import create_pagination_page

roles_permissions_router = APIRouter(prefix="/permission")

PermissionPage = create_pagination_page(PermissionRead)

@roles_permissions_router.get("", response_model=PermissionPage, description='Get all permissions',
                              dependencies=[Depends(require_all_permissions(Permissions.PERMISSIONS_READ_ALL))])
async def get_all_permissions(db: AsyncSession = Depends(get_async_db)):
    permission_service = PermissionService(db)
    stmt = await permission_service.get_all(get_stmt=True)
    return await paginate(db, stmt)

@roles_permissions_router.get("/{permission_id}", response_model=PermissionRead, description='Get one permission',
                              dependencies=[Depends(require_all_permissions(Permissions.PERMISSIONS_READ_ALL))])
async def get_one_permission(permission_id: int, db: AsyncSession = Depends(get_async_db)):
    permission_service = PermissionService(db)
    permission = await permission_service.get(permission_id)
    if not permission:
        raise NotFoundProblem(detail="Permission not found")
    return permission




