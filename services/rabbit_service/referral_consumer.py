import json

from aio_pika.abc import AbstractIncomingMessage
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from core.logger import logger
from services.rabbit_service.base import RabbitBaseService
from services.rabbit_service.service import RabbitMQPublisher
from services.referral.event_handlers import ReferralEventHandler


class ReferralRabbitConsumer(RabbitBaseService):
    def __init__(self, db_session_factory: async_sessionmaker[AsyncSession], publisher: RabbitMQPublisher,
                 *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db_session_factory = db_session_factory
        self.publisher = publisher

    async def process_message(self, message: AbstractIncomingMessage):
        payload = json.loads(message.body.decode("utf-8")).get("payload")
        routing_key = message.routing_key
        logger.info("Received new message", extra={"routing_key": routing_key, "payload": payload})
        async with self.db_session_factory() as session:
            await ReferralEventHandler(session, self.publisher).handle(routing_key, payload)
