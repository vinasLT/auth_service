import asyncio

from sqlalchemy.ext.asyncio import AsyncSession
import secrets
from core.logger import logger
from custom_exceptions import TooManyRequests
from database.crud.verification_code import VerificationCodeService
from database.models import User
from database.models.verification_code import Destination, VerificationCodeRoutingKey
from rabbit_service.service import RabbitMQPublisher


class CodeService:
    CODE_LENGTH = 6
    CODE_EXPIRY_MINUTES = 10

    def __init__(self, user_uuid: str):
        self.user_uuid = user_uuid

    @classmethod
    def generate_code(cls) -> str:
        return ''.join(secrets.choice('0123456789') for _ in range(cls.CODE_LENGTH))


class VerificationCodeSender:
    def __init__(self, db: AsyncSession, rabbit_mq_service: RabbitMQPublisher):
        self.db = db
        self.rabbit_mq_service = rabbit_mq_service
        self.code_service = VerificationCodeService(db)

    async def send_code(self, user: User, destination: Destination, routing_key: VerificationCodeRoutingKey):
        if not await self.code_service.can_send_new_code(user_id=user.id, destination=destination):
            logger.debug('Wait before send new code, wait around 1 minute', extra={
                "user_id": user.id,
                "destination": destination
            })
            raise TooManyRequests(
                detail="Wait before send new code, wait around 1 minute",
                status=429,
                title='Too many requests'
            )


        new_code = await self.code_service.create_code_with_deactivation(
            user_id=user.id,
            code=CodeService.generate_code(),
            destination=destination,
            routing_key=routing_key
        )

        payload = {
            "user_uuid": user.uuid_key,
            'code': new_code.code,
            'destination': destination,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'expire_minutes': CodeService.CODE_EXPIRY_MINUTES,
            'phone_number': user.phone_number
        }

        await self.rabbit_mq_service.publish(routing_key=routing_key.value, payload=payload)
        logger.info(f'Code sent', extra=payload)

        return {"message": "Code sent"}

if __name__ == "__main__":
    async def main():
        payload = {
            "user_uuid": 'oijkf309430fjdpsof',
            'code': 'code',
            'destination': 'sms',
            'first_name': 'TEST',
            'last_name': 'TEST',
            'email': 'peyrovskaaa@gmail.com',
            'expire_minutes': CodeService.CODE_EXPIRY_MINUTES,
            'phone_number': '+380634379178'
        }
        servbice = RabbitMQPublisher()
        await servbice.connect()
        await servbice.publish(routing_key=VerificationCodeRoutingKey.ACCOUNT_VERIFICATION, payload=payload)
        logger.info(f'Code sent', extra=payload)
    asyncio.run(main())




