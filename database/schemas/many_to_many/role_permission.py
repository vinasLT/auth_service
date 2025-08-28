from typing import Optional

from pydantic import BaseModel, ConfigDict


class RolePermissionCreate(BaseModel):
    role_id: int
    permission_id: int

class RolePermissionUpdate(BaseModel):
    role_id: Optional[int] = None
    permission_id: Optional[int] = None

class RolePermissionRead(RolePermissionCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)
