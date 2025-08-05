from pydantic import BaseModel, Field


class RefreshTokenIn(BaseModel):
    access_token: str = Field(..., description="access JWT token")
    refresh_token: str = Field(..., description="refresh JWT token")


