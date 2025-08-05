from datetime import datetime, UTC
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models import Base
from database.models.role import role_permissions

if TYPE_CHECKING:
    from database.models.role import Role, role_permissions


class Permission(Base):
    __tablename__ = 'permission'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    resource: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # e.g., "users", "posts", etc.
    action: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # e.g., "read", "write", "delete"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    roles: Mapped[List["Role"]] = relationship(
        secondary=role_permissions,
        back_populates="permissions"
    )