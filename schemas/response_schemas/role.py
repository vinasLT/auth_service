from pydantic import BaseModel, Field


class AssignRoleToUserIn(BaseModel):
    role_id: int = Field(..., description="Role ID")
    user_uuid: str = Field(..., description="User UUID")