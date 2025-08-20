from datetime import datetime, timezone
from loguru import logger as loguru_logger
import json

from config import settings, Environment


class ConsoleLogger:
    def __init__(
            self,
            service_name: str,
            environment: str = "",
            include_extra: bool = True
    ) -> None:
        self.service_name = service_name
        self.environment = environment
        self.include_extra = include_extra

    def sink(self, message) -> None:
        record = message.record
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "service": self.service_name,
            "environment": self.environment,
            "level": record["level"].name,
            "level_value": record["level"].no,
            "logger": record["name"],
            "message": record["message"],
            "module": record["module"],
            "function": record["function"],
            "line": record["line"],
            "file": record["file"].path,
            "thread": {
                "name": record["thread"].name,
                "id": record["thread"].id
            },
            "process": {
                "name": record["process"].name,
                "id": record["process"].id
            },
            "time": record["time"].isoformat()
        }

        # Добавляем exception если есть
        exc = record.get("exception")
        if exc and (exc.type or exc.value):
            doc["exception"] = {
                "type": exc.type.__name__ if exc.type else None,
                "value": str(exc.value) if exc.value else None,
                "traceback": exc.traceback or None
            }

        # Добавляем extra данные если включено
        if self.include_extra:
            extra = record.get("extra")
            if extra:
                doc["extra"] = extra

        # Выводим в консоль в формате JSON для Loki
        print(json.dumps(doc, ensure_ascii=False))


def setup_logging(
        service_name: str,
        environment: str,
        level: str = "INFO",
        include_extra: bool = True
):
    console_logger = ConsoleLogger(
        service_name=service_name,
        environment=environment,
        include_extra=include_extra
    )
    loguru_logger.remove()
    loguru_logger.add(console_logger.sink, format="{message}", level=level, backtrace=True, diagnose=True, enqueue=True)
    return loguru_logger.bind(service=service_name, environment=environment)


logger = setup_logging(
    service_name=settings.APP_NAME,
    environment="dev" if settings.ENVIRONMENT == Environment.DEVELOPMENT else "prod",
    level="DEBUG" if settings.DEBUG else "INFO",
    include_extra=True
)
