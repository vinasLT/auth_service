from pydantic import BaseModel, Field


class RefreshTokenIn(BaseModel):
    refresh_token: str = Field(..., description="refresh JWT token")


