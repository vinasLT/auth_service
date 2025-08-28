from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from database.models import Base
if TYPE_CHECKING:
    from database.models.permission import Permission
    from database.models.role import Role

class RolePermission(Base):
    __tablename__ = 'role_permissions'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey('role.id'))
    permission_id: Mapped[int] = mapped_column(ForeignKey('permission.id'))

