from typing import Optional

from pydantic import BaseModel, ConfigDict


class UserRoleCreate(BaseModel):
    role_id: int
    user_id: int

class UserRoleUpdate(BaseModel):
    role_id: Optional[int] = None
    user_id: Optional[int] = None

class UserRoleRead(UserRoleCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)