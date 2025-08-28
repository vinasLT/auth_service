from typing import Optional

from pydantic import Field

from database.schemas.role import RoleCreate, RoleUpdate


class CreateRoleIn(RoleCreate):
    permission_ids: Optional[list[int]] = Field([], description="List of permission ids")

class UpdateRoleIn(RoleUpdate):
    permission_ids: Optional[list[int]] = Field(None, description="List of permission ids")
