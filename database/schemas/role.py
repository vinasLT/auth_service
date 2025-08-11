from typing import Optional

from pydantic import BaseModel, ConfigDict


class RoleCreate(BaseModel):
    name: str
    description: str = None

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class RoleRead:
    id: int

    model_config = ConfigDict(from_attributes=True)
