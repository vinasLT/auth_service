from typing import Optional

from pydantic import BaseModel


class RolePermissionCreate(BaseModel):
    role_id: int
    permission_id: int

class RolePermissionUpdate(BaseModel):
    role_id: Optional[int] = None
    permission_id: Optional[int] = None

class RolePermissionRead(RolePermissionCreate):
    id: int

    class Config:
        from_attributes = True
