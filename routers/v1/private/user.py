from fastapi import APIRouter, Depends, Query, Path
from rfc9457 import NotFoundProblem
from sqlalchemy.ext.asyncio import AsyncSession

from config import Permissions
from database.crud.user import UserService
from database.db.session import get_async_db

from fastapi_pagination.ext.sqlalchemy import paginate

from database.schemas.user import UserRead
from dependencies.security import JWTUser, require_all_permissions
from schemas.request_schemas.users import UserSearchIn
from schemas.response_schemas.users import FullUserOut
from utils.pagination_page import create_pagination_page

user_control_router = APIRouter(prefix="/user")


UserPage = create_pagination_page(FullUserOut)

@user_control_router.get("", response_model=UserPage, description='All users view',
                         dependencies=[Depends(require_all_permissions(Permissions.USERS_READ_ALL))])
async def user_router(data: UserSearchIn = Query(...),
                      db: AsyncSession = Depends(get_async_db)):
    user_service = UserService(db)

    stmt = await user_service.get_all_users(get_stmt=True, search=data.search, include_inactive=data.include_inactive)
    return await paginate(db, stmt)

@user_control_router.get("/me", response_model=UserRead, description='Get current user')
async def user_router(user: JWTUser = Depends(require_all_permissions(Permissions.USERS_READ_OWN)),
                      db: AsyncSession = Depends(get_async_db)):
    user_service = UserService(db)
    user = await user_service.get_user_by_uuid(user.id)
    return user


@user_control_router.get("/{user_uuid}", response_model=FullUserOut, description='Detail user',
                         dependencies=[Depends(require_all_permissions(Permissions.USERS_READ_ALL))])
async def user_router(user_uuid: str = Path(...), db: AsyncSession = Depends(get_async_db)):
    user_service = UserService(db)
    user = await user_service.get_user_by_uuid(user_uuid)
    if not user:
        raise NotFoundProblem(detail="User not found")
    return user













