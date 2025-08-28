from fastapi import APIRouter, Body, Depends
from rfc9457 import NotFoundProblem, BadRequestProblem
from sqlalchemy.ext.asyncio import AsyncSession

from auth.service import AuthService
from base_checks import check_user
from custom_exceptions import InvalidCodeProblem

from database.crud.user import UserService
from database.crud.verification_code import VerificationCodeService
from database.db.session import get_async_db
from database.models.verification_code import Destination
from database.schemas.user import UserUpdate, UserRead
from deps import get_auth_service, get_rate_limiter
from schemas.request_schemas.password_reset import ResetPasswordIn

password_reset_router = APIRouter()

@password_reset_router.post("", response_model=UserRead,
                            status_code=200,
                            summary="Password reset by email request",
                            description="Password reset by email request",
                            dependencies=[get_rate_limiter(times=15, seconds=120)])
async def reset_password_by_email(reset_pass_data: ResetPasswordIn = Body(...),
                                  db: AsyncSession = Depends(get_async_db),
                                  auth_service: AuthService = Depends(get_auth_service)):
    user_service = UserService(db)
    code_service = VerificationCodeService(db)

    user = await user_service.get_by_email(email=str(reset_pass_data.email))
    if not user:
        raise NotFoundProblem(detail="User not found")

    check_user(user)

    if not await code_service.verify_code(user_id=user.id, code=reset_pass_data.code, destination=Destination.EMAIL):
        raise InvalidCodeProblem(detail='Invalid code')

    if auth_service.verify_password(reset_pass_data.new_password1, str(user.password_hash)):
        raise BadRequestProblem(detail="Password cannot be the same as the old")

    new_password_hash = auth_service.hash_password(str(reset_pass_data.new_password1))

    user_updated = UserUpdate(password_hash=new_password_hash)

    updated_user = await user_service.update(user.id, user_updated)

    return updated_user




