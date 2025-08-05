from datetime import datetime, UTC
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import DateTime, String, Table, ForeignKey, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models import Base

if TYPE_CHECKING:
    from database.models.user_role import UserRole
    from database.models.permission import Permission

role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', ForeignKey('role.id'), primary_key=True),
    Column('permission_id', ForeignKey('permission.id'), primary_key=True)
)


class Role(Base):
    __tablename__ = 'role'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    is_default: Mapped[bool] = mapped_column(default=False)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    users: Mapped[List["UserRole"]] = relationship(back_populates="role")
    permissions: Mapped[List["Permission"]] = relationship(
        secondary=role_permissions,
        back_populates="roles",
        cascade="all"
    )