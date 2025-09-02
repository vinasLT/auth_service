
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from database.models.permission import ActionEnum


class PermissionCreate(BaseModel):
    name: str = Field(..., description="Permission name")
    description: Optional[str] = Field(None, description="Permission description")
    resource: str = Field(..., description="Permission resource, 'auth.user.all' (like scope)")
    action: ActionEnum = Field(..., description="Permission action")

class PermissionUpdate(BaseModel):
    name: Optional[str] = Field(None, description="Permission name")
    description: Optional[str] = Field(None, description="Permission description")
    resource: Optional[str] = Field(None, description="Permission resource, 'auth.user.all' (like scope)")
    action: Optional[ActionEnum] = Field(None, description="Permission action")

class PermissionRead(PermissionCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


