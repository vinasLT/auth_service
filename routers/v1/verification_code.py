from fastapi import APIRouter, Depends, Path, Body
from rfc9457 import NotFoundProblem, BadRequestProblem
from sqlalchemy.ext.asyncio import AsyncSession

from code_service import CodeService, VerificationCodeSender
from core.logger import logger
from custom_exceptions import TooManyRequests, InvalidCodeProblem
from database.crud.user import UserService
from database.crud.verification_code import VerificationCodeService
from database.db.session import get_async_db
from database.models.verification_code import Destination
from database.schemas.user import UserUpdate
from deps import get_rate_limiter, get_rabbit_mq_service
from rabbit_service.service import RabbitMQPublisher
from request_schemas.registration import EmailIn
from request_schemas.verification_code import CodeIn

verification_code_router = APIRouter()


@verification_code_router.post("/{user_uuid}/{destination}/send-code",
                               description="Send a phone verification code to the user",
                               dependencies=[get_rate_limiter(times=4, seconds=1800)])
async def send_code(
        user_uuid: str = Path(description='user uuid, retrieved after registration'),
        destination: Destination = Path(description='where code need to be send'),
        db: AsyncSession = Depends(get_async_db),
        rabbit_mq_service: RabbitMQPublisher = Depends(get_rabbit_mq_service)
):
    user_service = UserService(db)
    user = await user_service.get_user_by_uuid(user_uuid)

    if not user:
        raise NotFoundProblem(detail="User not found")

    sender = VerificationCodeSender(db, rabbit_mq_service)
    return await sender.send_code(user, destination, "auth.send_code")

@verification_code_router.post('/verify/{user_uuid}/{destination}', description="Verify a phone verification code",
                               dependencies=[get_rate_limiter(times=15, seconds=1800)])
async def verify_code(user_uuid: str = Path(description='user uuid, retrieved after registration'),
                            destination: Destination = Path(description='from where you expect code'),
                            code: CodeIn = Body(...),
                            db: AsyncSession = Depends(get_async_db)):
    user_service = UserService(db)
    code_service = VerificationCodeService(db)

    user = await user_service.get_user_by_uuid(user_uuid)
    if not user:
        raise NotFoundProblem(detail="User not found")

    if not await code_service.verify_code(user_id=user.id, code=code.code, destination=destination):
        raise InvalidCodeProblem(detail=f"Invalid code")

    else:
        if destination == Destination.EMAIL:
            user_update = UserUpdate(email_verified=True)
        else:
            user_update = UserUpdate(phone_verified=True)

        await user_service.update(user.id, user_update)
        return {"message": "Code verified"}


@verification_code_router.post("/email/send-code",
                               description="Send an email verification code to the user",
                               dependencies=[get_rate_limiter(times=4, seconds=1800)])
async def send_email_code(
        request: EmailIn,
        db: AsyncSession = Depends(get_async_db),
        rabbit_mq_service: RabbitMQPublisher = Depends(get_rabbit_mq_service)
):
    user_service = UserService(db)
    user = await user_service.get_by_email(str(request.email))

    if not user:
        raise NotFoundProblem(detail="User not found")

    sender = VerificationCodeSender(db, rabbit_mq_service)
    return await sender.send_code(user, Destination.EMAIL, "auth.send_email_code")




