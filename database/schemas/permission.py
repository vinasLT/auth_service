from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class PermissionCreate(BaseModel):
    name: str
    description: str = None
    resource: str = None
    action: str = None

class PermissionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None

class PermissionRead(PermissionCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


