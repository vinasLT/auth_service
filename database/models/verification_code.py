import enum
from datetime import datetime

from sqlalchemy import ForeignKey, String, Enum, DateTime
from sqlalchemy.orm import Mapped
from sqlalchemy.testing.schema import mapped_column

from database.models import Base

class Destination(str, enum.Enum):
    EMAIL = "email"
    PHONE = "sms"


class VerificationCode(Base):
    __tablename__ = 'verification_code'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    uuid_key: Mapped[str] = mapped_column(String, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    code: Mapped[str] = mapped_column(String, nullable=False)
    destination: Mapped[Destination] = mapped_column(Enum(Destination), nullable=False)

    is_verified: Mapped[bool] = mapped_column(default=False)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

