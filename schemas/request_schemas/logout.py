from pydantic import BaseModel, Field


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., description="refresh JWT token")