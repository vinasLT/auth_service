from abc import abstractmethod, ABC
from typing import Optional

from aio_pika.abc import AbstractRobustConnection, AbstractRobustExchange, AbstractRobustQueue, \
    AbstractIncomingMessage, ConsumerTag, ExchangeType

from config import settings
from core.logger import logger


class RabbitBaseService(ABC):
    def __init__(self, connection: AbstractRobustConnection,
                 routing_keys: list[str],
                 exchange_name: str = settings.RABBITMQ_EXCHANGE_NAME,
                 prefetch_count: int = 10,
                 durable: bool = True,
                 queue_name: str = settings.RABBITMQ_QUEUE_NAME,
                 max_retries: int = 3):

        self.queue_name = queue_name
        self.connection = connection
        self.exchange_name = exchange_name
        self.prefetch_count = prefetch_count
        self.durable = durable
        self.routing_keys = routing_keys
        self.max_retries = max_retries

        self.exchange: Optional[AbstractRobustExchange] = None
        self.queue: Optional[AbstractRobustQueue] = None
        self.consumer_tag: Optional[ConsumerTag] = None

        logger.info(
            "RabbitService initialized",
            extra={
                "queue_name": self.queue_name,
                "exchange_name": self.exchange_name,
                "routing_keys": self.routing_keys,
                "prefetch_count": self.prefetch_count,
                "max_retries": self.max_retries
            }
        )

    async def set_up(self):
        try:
            logger.info(
                "Setting up RabbitMQ connection",
                extra={
                    "exchange_name": self.exchange_name,
                    "queue_name": self.queue_name
                }
            )

            channel = await self.connection.channel()
            await channel.set_qos(prefetch_count=self.prefetch_count)

            self.exchange = await channel.declare_exchange(
                self.exchange_name,
                type=ExchangeType.TOPIC,
                durable=self.durable
            )

            logger.debug(
                "Exchange declared successfully",
                extra={"exchange_name": self.exchange_name}
            )

            self.queue = await channel.declare_queue(
                self.queue_name,
                durable=self.durable
            )

            logger.debug(
                "Queue declared successfully",
                extra={"queue_name": self.queue_name}
            )

            for routing_key in self.routing_keys:
                await self.queue.bind(self.exchange, routing_key=routing_key)
                logger.debug(
                    "Queue bound to exchange",
                    extra={
                        "queue_name": self.queue_name,
                        "exchange_name": self.exchange_name,
                        "routing_key": routing_key
                    }
                )

            logger.info(
                "RabbitMQ setup completed successfully",
                extra={
                    "exchange_name": self.exchange_name,
                    "queue_name": self.queue_name,
                    "routing_keys": self.routing_keys
                }
            )

        except Exception as e:
            logger.error(
                "Failed to set up RabbitMQ connection",
                extra={
                    "exchange_name": self.exchange_name,
                    "queue_name": self.queue_name,
                    "error": str(e)
                },
                exc_info=True
            )
            raise e

    async def start_consuming(self):
        logger.info(
            "Starting to consume messages",
            extra={"queue_name": self.queue_name}
        )

        self.consumer_tag = await self.queue.consume(self.process_message_wrapper, no_ack=False)

        logger.debug(
            "Consumer started",
            extra={
                "queue_name": self.queue_name,
                "consumer_tag": self.consumer_tag
            }
        )

        logger.info("Consumer is running. Waiting for messages...")

    @abstractmethod
    async def process_message(self, message: AbstractIncomingMessage):
        ...

    async def process_message_wrapper(self, message: AbstractIncomingMessage):
        message_id = message.message_id or "unknown"
        routing_key = message.routing_key
        delivery_tag = message.delivery_tag

        logger.debug(
            "Processing message",
            extra={
                "message_id": message_id,
                "routing_key": routing_key,
                "delivery_tag": delivery_tag,
                "redelivered": message.redelivered,
                "headers": dict(message.headers) if message.headers else None
            }
        )

        try:
            await self.process_message(message)
            await message.ack()

            logger.info(
                "Message processed successfully",
                extra={
                    "message_id": message_id,
                    "routing_key": routing_key,
                    "delivery_tag": delivery_tag
                }
            )

        except Exception as e:
            logger.error(
                "Error processing message",
                extra={
                    "message_id": message_id,
                    "routing_key": routing_key,
                    "delivery_tag": delivery_tag,
                    "redelivered": message.redelivered,
                    "error": str(e)
                },
                exc_info=True
            )

            if message.redelivered or delivery_tag >= self.max_retries:
                await message.reject(requeue=False)
                logger.warning(
                    "Message rejected permanently (max retries reached or redelivered)",
                    extra={
                        "message_id": message_id,
                        "routing_key": routing_key,
                        "delivery_tag": delivery_tag,
                        "redelivered": message.redelivered,
                        "max_retries": self.max_retries
                    }
                )
            else:
                await message.reject(requeue=True)
                logger.warning(
                    "Message rejected and requeued for retry",
                    extra={
                        "message_id": message_id,
                        "routing_key": routing_key,
                        "delivery_tag": delivery_tag,
                        "retry_count": delivery_tag
                    }
                )

    async def stop_consuming(self):
        logger.info("Stopping message consumption")

        try:
            await self.connection.close()

        except Exception as e:
            logger.error(
                "Error while stopping consumption",
                extra={"error": str(e)},
                exc_info=True
            )
            raise e



