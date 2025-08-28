from datetime import datetime, UTC
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models import Base

if TYPE_CHECKING:
    from database.models.many_to_many.user_role import UserRole
    from database.models.user import User
    from database.models.permission import Permission


class Role(Base):
    __tablename__ = 'role'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    is_default: Mapped[bool] = mapped_column(default=False)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


    permissions: Mapped[List["Permission"]] = relationship(
        "Permission",
        back_populates="roles",
        secondary="role_permissions",
        lazy="selectin"
    )

    users: Mapped[List["User"]] = relationship(
        "User",
        secondary="user_roles",
        back_populates="roles",
        lazy="selectin"
    )