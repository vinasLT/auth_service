from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class LoginHistoryCreate(BaseModel):
    user_id: str
    success: bool
    login_at: datetime = None
    ip_address: str = None
    user_agent: str = None
    device_info: str = None
    location: str = None
    failure_reason: str = None


class LoginHistoryUpdate(BaseModel):
    user_id: Optional[str] = None
    success: Optional[bool] = None
    login_at: Optional[datetime] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_info: Optional[str] = None
    location: Optional[str] = None
    failure_reason: Optional[str] = None


class LoginHistoryRead(LoginHistoryCreate):
    id: int
    login_at: datetime

    class Config:
        from_attributes = True