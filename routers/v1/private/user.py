import grpc
from fastapi import APIRouter, Body, Depends, Query, Path, Response
from rfc9457 import NotFoundProblem, BadRequestProblem, Problem
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from auth_utils.service import AuthService
from config import Permissions
from core.logger import logger
from database.crud.user import UserService
from database.db.session import get_async_db
from database.models import User
from database.schemas.user import UserRead
from deps import get_auth_service
from dependencies.security import JWTUser, require_all_permissions
from fastapi_pagination.ext.sqlalchemy import paginate
from schemas.request_schemas.registration import UserIn
from schemas.request_schemas.users import UserSearchIn
from schemas.response_schemas.users import FullUserOut, DetailedUser, UserAccount, Plan
from services.user_registration_service import create_or_update_user
from services.rpc_server_client.account import AccountRpcClient
from utils.pagination_page import create_pagination_page

user_control_router = APIRouter(prefix="/user")


UserPage = create_pagination_page(FullUserOut)

async def _build_detailed_user(user_service: UserService, user_uuid: str, user: User) -> DetailedUser:
    roles_permissions = await user_service.extract_roles_and_permissions_from_user(
        user_id=user.id,
        user=user,
    )

    try:
        async with AccountRpcClient() as rpc_client:
            account = await rpc_client.get_account_info(user_uuid=user_uuid)
            plan = Plan(
                name=account.plan.name,
                description=account.plan.description,
                bid_power=account.plan.bid_power,
                price=account.plan.price,
                max_bid_one_time=account.plan.max_bid_one_time
            )
            user_account = UserAccount(balance=account.balance, plan=plan)
    except grpc.aio.AioRpcError as e:
        logger.exception(f"Error on get account by uuid: {e.details()}")
        raise BadRequestProblem(detail=f"Error on get account by uuid: {e.details()}")

    base_user = UserRead.model_validate(user)

    return DetailedUser(
        **base_user.model_dump(),
        roles=roles_permissions.get("roles", []),
        permissions=roles_permissions.get("permissions", []),
        account=user_account
    )

@user_control_router.get("", response_model=UserPage, description='All users view',
                         dependencies=[Depends(require_all_permissions(Permissions.USERS_READ_ALL))])
async def user_router(data: UserSearchIn = Query(...),
                      db: AsyncSession = Depends(get_async_db)):
    user_service = UserService(db)

    stmt = await user_service.get_all_users(get_stmt=True, search=data.search, include_inactive=data.include_inactive)
    return await paginate(db, stmt)

@user_control_router.get("/me", response_model=DetailedUser, description='Get current user')
async def user_router(current_user: JWTUser = Depends(require_all_permissions(Permissions.USERS_READ_OWN)),
                      db: AsyncSession = Depends(get_async_db)):
    user_service = UserService(db)
    db_user = await user_service.get_user_by_uuid(current_user.id)
    if not db_user:
        raise NotFoundProblem(detail="User not found")

    return await _build_detailed_user(user_service=user_service, user_uuid=current_user.id, user=db_user)



@user_control_router.get("/{user_uuid}", response_model=DetailedUser, description='Detail user',
                         dependencies=[Depends(require_all_permissions(Permissions.USERS_READ_ALL))])
async def user_router(user_uuid: str = Path(...), db: AsyncSession = Depends(get_async_db)):
    user_service = UserService(db)
    user = await user_service.get_user_by_uuid(user_uuid)
    if not user:
        raise NotFoundProblem(detail="User not found")
    return await _build_detailed_user(user_service=user_service, user_uuid=user_uuid, user=user)


@user_control_router.post(
    "/create-manually",
    response_model=DetailedUser,
    status_code=201,
    description="Create new user manually",
    dependencies=[Depends(require_all_permissions(Permissions.USERS_WRITE_ALL))],
)
async def create_new_user(
    user_data: UserIn = Body(..., description="User registration payload"),
    response: Response = None,
    db: AsyncSession = Depends(get_async_db),
    auth_service: AuthService = Depends(get_auth_service),
) -> DetailedUser:
    logger.info(
        "Manual user creation attempt",
        extra={"email": user_data.email, "phone_number": user_data.phone_number},
    )
    try:
        password_hash = auth_service.hash_password(user_data.password)
        user = await create_or_update_user(
            db,
            user_data,
            password_hash,
            mark_verified=True,
            log_context="Manual user creation",
            is_created_manually=True,
        )
        user_service = UserService(db)
        response.status_code = status.HTTP_201_CREATED
        return await _build_detailed_user(
            user_service=user_service,
            user_uuid=user.uuid_key,
            user=user,
        )
    except Problem:
        raise
    except Exception as e:
        logger.error(
            "Manual user creation failed - unexpected error",
            extra={
                "email": user_data.email,
                "phone_number": user_data.phone_number,
                "error": str(e),
                "error_type": type(e).__name__,
            },
        )
        raise



