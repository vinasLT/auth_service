from datetime import datetime, UTC
from typing import List, TYPE_CHECKING

from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship, Mapped, mapped_column

from database.models import Base

if TYPE_CHECKING:
    from database.models.many_to_many.user_role import UserRole
    from database.models.role import Role


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    uuid_key: Mapped[str] = mapped_column(String, unique=True, index=True)

    first_name: Mapped[str] = mapped_column(String)
    last_name: Mapped[str] = mapped_column(String)

    language: Mapped[str] = mapped_column(String, default='en')

    password_hash: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, index=True)
    username: Mapped[str] = mapped_column(String, index=True)
    phone_number: Mapped[str] = mapped_column(String, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    phone_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),
                                                 onupdate=lambda: datetime.now(UTC))

    roles: Mapped[List["Role"]] = relationship(
        "Role",
        secondary="user_roles",
        back_populates="users",
        lazy="selectin"
    )


