from datetime import datetime, UTC
from typing import List, TYPE_CHECKING

from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship, Mapped, mapped_column

from database.models import Base

if TYPE_CHECKING:
    from database.models.many_to_many.user_role import UserRole


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    uuid_key: Mapped[str] = mapped_column(String, unique=True, index=True)

    password_hash: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, index=True)
    username: Mapped[str] = mapped_column(String, index=True)
    phone_number: Mapped[str] = mapped_column(String, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),
                                                 onupdate=lambda: datetime.now(UTC))

    roles: Mapped[List["UserRole"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan"
    )
