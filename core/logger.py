from datetime import datetime, timezone
from loguru import logger as loguru_logger
import json
import os

from config import settings


class FileLogger:
    def __init__(
        self,
        service_name: str,
        log_dir: str = "logs",
        index_prefix: str = "logs",
        environment: str = ""
    ) -> None:
        self.service_name = service_name
        self.environment = environment
        self.index_prefix = index_prefix
        os.makedirs(log_dir, exist_ok=True)
        self.log_path = os.path.join(
            log_dir,
            f"{self.index_prefix}-{self.service_name}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}.jsonl"
        )

    def _make_index_name(self) -> str:
        return os.path.basename(self.log_path)

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
        exc = record.get("exception")
        if exc and (exc.type or exc.value):
            doc["exception"] = {
                "type": exc.type.__name__ if exc.type else None,
                "value": str(exc.value) if exc.value else None,
                "traceback": exc.traceback or None
            }
        extra = record.get("extra")
        if extra:
            doc["extra"] = extra
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")


def setup_file_logging(
    service_name: str,
    environment: str,
    log_dir: str = "logs",
    level: str = "INFO"
):
    file_logger = FileLogger(
        service_name=service_name,
        log_dir=log_dir,
        environment=environment
    )
    loguru_logger.remove()
    loguru_logger.add(file_logger.sink, format="{message}", level=level, backtrace=True, diagnose=True, enqueue=True)
    return loguru_logger.bind(service=service_name, environment=environment)

logger = setup_file_logging(service_name=settings.APP_NAME,
                            environment="dev" if settings.DEBUG else "prod",
                            level="DEBUG" if settings.DEBUG else "INFO")
