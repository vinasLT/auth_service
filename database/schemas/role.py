from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from database.schemas.permission import PermissionRead


class RoleCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=50, description="Role name")
    description: Optional[str] = Field(None, min_length=3, max_length=100, description="Role description")

class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=50, description="Role name")
    description: Optional[str] = Field(None, min_length=3, max_length=100, description="Role description")

class RoleRead(RoleCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)

class RoleReadWithPermissions(RoleRead):
    permissions: list[PermissionRead] = []