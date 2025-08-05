from typing import Optional

from pydantic import BaseModel


class RoleCreate(BaseModel):
    name: str
    description: str = None

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class RoleRead:
    id: int

    class Config:
        from_attributes = True
