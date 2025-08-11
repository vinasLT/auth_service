from fastapi import APIRouter, Depends, Path, Body
from rfc9457 import NotFoundProblem, BadRequestProblem
from sqlalchemy.ext.asyncio import AsyncSession

from code_service import CodeService
from custom_exceptions import TooManyRequests
from database.crud.user import UserService
from database.crud.verification_code import VerificationCodeService
from database.db.session import get_async_db
from database.models.verification_code import Destination
from deps import get_rate_limiter, get_rabbit_mq_service
from rabbit_service.service import RabbitMQPublisher
from request_schemas.verification_code import CodeIn

verification_code_router = APIRouter()

@verification_code_router.post("/{user_uuid}/{destination}/send-code", description="Send a phone verification code to the user",
                              dependencies=[get_rate_limiter(times=4, seconds=1800)])
async def send_code(user_uuid: str = Path(description='user uuid, retrieved after registration'),
                    destination: Destination = Path(description='where code need to be send'),
                    db: AsyncSession = Depends(get_async_db),
                    rabbit_mq_service: RabbitMQPublisher = Depends(get_rabbit_mq_service)):
    user_service = UserService(db)
    code_service = VerificationCodeService(db)



    user = await user_service.get_user_by_uuid(user_uuid)
    if not user:
        raise NotFoundProblem(detail="User not found")

    if not code_service.can_send_new_code(user_id=user.id, destination=destination):
        raise TooManyRequests(detail=f"Wait before send new code, wait around 1 minute", title='Too many requests')

    new_code = await code_service.create_code_with_deactivation(user_id=user.id, code=CodeService.generate_code(), destination=destination)

    payload = {"user_uuid": user.uuid_key,
               'code': new_code.code,
               'destination': destination,
               'first_name': user.first_name,
               'last_name': user.last_name,
               'email': user.email,
               'expire_minutes': CodeService.CODE_EXPIRY_MINUTES,
               'phone_number': user.phone_number}
    await rabbit_mq_service.publish(routing_key="notification.auth.send_code", payload=payload)
    return {"message": "Code sent"}

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
        raise BadRequestProblem(detail="Invalid code")
    else:
        return {"message": "Code verified"}



