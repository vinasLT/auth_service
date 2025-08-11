from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

from database.models.verification_code import Destination


class VerificationCodeCreate(BaseModel):
    user_id: int
    code: str
    uuid_key: str
    destination: Destination
    is_verified: Optional[bool] = False
    expires_at: datetime
    created_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None

class VerificationCodeUpdate(BaseModel):
    user_id: Optional[int] = None
    uuid_key: Optional[str] = None
    code: Optional[str] = None
    destination: Optional[Destination] = None
    is_verified: Optional[bool] = None
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None


class VerificationCodeRead(VerificationCodeCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)