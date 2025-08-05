from datetime import datetime, UTC
from enum import Enum
from sqlalchemy import Enum as SAEnum, String, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from database.models import Base


class AlgorithmsEnum(str, Enum):
    RSASSA_PSS_SHA_512 = "RSASSA_PSS_SHA_512"
    RSASSA_PSS_SHA_384 = "RSASSA_PSS_SHA_384"
    RSASSA_PSS_SHA_256 = "RSASSA_PSS_SHA_256"

class SingingKey(Base):
    __tablename__ = "singing_key"

    id: Mapped[int] = mapped_column(primary_key=True, index=True, autoincrement=True)
    key_arn: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    alg: Mapped[AlgorithmsEnum] = mapped_column(String, SAEnum(AlgorithmsEnum), index=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

