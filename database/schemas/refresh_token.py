from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class RefreshTokenCreate(BaseModel):
    jti: str
    user_id: int
    token_family: str
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    device_name: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    is_active: Optional[bool] = True
    revoked_at: Optional[datetime] = None
    used_at: Optional[datetime] = None
    replaced_by: Optional[int] = None


class RefreshTokenUpdate(BaseModel):
    jti: Optional[str] = None
    user_id: Optional[int] = None
    token_family: Optional[str] = None
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    device_name: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    is_active: Optional[bool] = None
    revoked_at: Optional[datetime] = None
    used_at: Optional[datetime] = None
    replaced_by: Optional[int] = None


class RefreshTokenRead(RefreshTokenCreate):
    id: int
    issued_at: datetime
    expires_at: datetime
    is_active: bool

    class Config:
        from_attributes = True
