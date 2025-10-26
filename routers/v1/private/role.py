from fastapi import APIRouter, Depends, Path, Body, Request
from fastapi_pagination.ext.sqlalchemy import paginate
from rfc9457 import NotFoundProblem, ConflictProblem
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from auth.service import AuthService, TokenType
from config import Permissions
from core.logger import logger
from database.crud.refresh_token import RefreshTokenService
from database.crud.role import RoleService
from database.crud.user import UserService
from database.db.session import get_async_db
from database.schemas.role import RoleReadWithPermissions
from dependencies.security import require_all_permissions, JWTUser
from deps import get_auth_service
from schemas.request_schemas.role import CreateRoleIn, UpdateRoleIn
from schemas.response_schemas.users import FullUserOut
from utils.pagination_page import create_pagination_page

roles_router = APIRouter( prefix='/role')

RolePage = create_pagination_page(RoleReadWithPermissions)


@roles_router.get("", response_model=RolePage, description='Get all roles', name='get_all_roles',
                              dependencies=[Depends(require_all_permissions(Permissions.ROLES_READ_ALL))])
async def get_all_roles(db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    stmt = await role_service.get_all(get_stmt=True)
    return await paginate(db, stmt)


@roles_router.get("/{role_id}", response_model=RoleReadWithPermissions, description='Get one role', name='get_role',
                              dependencies=[Depends(require_all_permissions(Permissions.ROLES_READ_ALL))])
async def get_one_role(role_id: int, db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    role = await role_service.get(role_id)
    if not role:
        raise NotFoundProblem(detail="Role not found")
    return role

@roles_router.post("", response_model=RoleReadWithPermissions, description='Create one role',
                   name='create_role', status_code=201,
                   dependencies=[Depends(require_all_permissions(Permissions.ROLES_READ_ALL,
                                                                 Permissions.ROLES_WRITE_ALL))])
async def create_one_role(role: CreateRoleIn = Body(...), db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    try:
        new_role = await role_service.create_with_permissions(role)
    except IntegrityError as e:
        logger.exception('Error while creating role:', extra={'error': e})
        await db.rollback()
        raise ConflictProblem(detail='Role already exists')
    return new_role

@roles_router.put("/{role_id}", response_model=RoleReadWithPermissions, description='Update one role',
                  name='update_role',
                  dependencies=[Depends(require_all_permissions(Permissions.ROLES_WRITE_ALL,
                                                                Permissions.ROLES_READ_ALL))])
async def update_one_role(role_id: int = Path(...), updated_role: UpdateRoleIn = Body(...), db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    role = await role_service.update_with_permissions(role_id, updated_role)
    return role


@roles_router.delete("/{role_id}", description='Delete one role', name='delete_role',
                     status_code=204,
                     dependencies=[Depends(require_all_permissions(Permissions.ROLES_DELETE_ALL))])
async def delete_one_role(role_id: int, db: AsyncSession = Depends(get_async_db)):
    role_service = RoleService(db)
    role = await role_service.get(role_id)
    if not role:
        raise NotFoundProblem(detail="Role not found")
    await role_service.delete(role_id)
    return {'success': True}


@roles_router.api_route("/{role_id}/user/{user_uuid}",
                        methods=["POST", "DELETE"],
                        response_model=FullUserOut,
                        dependencies=[Depends(require_all_permissions(Permissions.ROLES_WRITE_ALL,
                                                                        Permissions.ROLES_READ_ALL,
                                                                        Permissions.USERS_WRITE_ALL,
                                                                        Permissions.USERS_READ_ALL))],
                        description='Assign/Unassign role to/from user')
async def manage_user_role(
        request: Request,
        role_id: int = Path(..., description='Role ID'),
        user_uuid: str = Path(..., description='User UUID'),
        db: AsyncSession = Depends(get_async_db),
        auth_service: AuthService = Depends(get_auth_service)
):
    role_service = RoleService(db)
    user_service = UserService(db)
    refresh_token_service = RefreshTokenService(db)

    user = await user_service.get_user_by_uuid(user_uuid)
    if not user:
        raise NotFoundProblem(detail="User not found")

    last_user_refresh_token = await refresh_token_service.get_last_refresh_token_by_user_id(user.id)
    role = await role_service.get_with_not_found_exception(role_id, 'role')

    if request.method == "POST":
        user.roles.append(role)
    else:
        user.roles.remove(role)

    await db.commit()
    await db.refresh(user)
    if last_user_refresh_token:
        await auth_service.blacklist_token(TokenType.ACCESS, last_user_refresh_token.jti)

    return user





