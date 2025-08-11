from typing import Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class UserSessionCreate(BaseModel):
    user_id: int
    session_key: str
    refresh_token_id: Optional[int] = None
    started_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    is_active: Optional[bool] = True
    terminated_at: Optional[datetime] = None


class UserSessionUpdate(BaseModel):
    user_id: Optional[int] = None
    session_key: Optional[str] = None
    refresh_token_id: Optional[int] = None
    started_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    is_active: Optional[bool] = None
    terminated_at: Optional[datetime] = None


class UserSessionRead(UserSessionCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)
