import enum
from datetime import datetime, UTC
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import String, DateTime, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models import Base

if TYPE_CHECKING:
    from database.models.role import Role

class ActionEnum(str, enum.Enum):
    WRITE = "write"
    READ = "read"
    DELETE = "delete"


class Permission(Base):
    __tablename__ = 'permission'

    __table_args__ = (
        UniqueConstraint('resource', 'action', name='unique_resource_action'),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    resource: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[ActionEnum] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    roles: Mapped[List["Role"]] = relationship(
        "Role",
        secondary="role_permissions",
        lazy="selectin",
        back_populates="permissions"
    )