from datetime import datetime, UTC
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import DateTime, String, Table, ForeignKey, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models import Base
from database.models.many_to_many.role_permission import RolePermission

if TYPE_CHECKING:
    from database.models.many_to_many.user_role import UserRole


class Role(Base):
    __tablename__ = 'role'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    is_default: Mapped[bool] = mapped_column(default=False)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    user_roles: Mapped[List["UserRole"]] = relationship(back_populates="role")

    role_permissions: Mapped[List["RolePermission"]] = relationship(
        "RolePermission",
        back_populates="role",
        cascade="all, delete-orphan"
    )