from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    access_token: str = Field(..., description='Access JWT token', json_schema_extra={"example": "Bearer <KEY>"})
    refresh_token: str = Field(..., description='Refresh JWT token', json_schema_extra={"example": "Bearer <KEY>"})


