from datetime import datetime, UTC
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, DateTime
from sqlalchemy.orm import mapped_column, Mapped, relationship

from database.models import Base

if TYPE_CHECKING:
    from database.models.user import User
    from database.models.role import Role

class UserRole(Base):
    __tablename__ = 'user_roles'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    role_id: Mapped[int] = mapped_column(ForeignKey('role.id'))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

