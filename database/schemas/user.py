from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    uuid_key: str
    password_hash: str
    email: EmailStr
    username: str
    phone_number: str

class UserUpdate(BaseModel):
    password: Optional[str] = Field(default=None, min_length=8, max_length=32)
    username: Optional[str] = None

class UserRead(BaseModel):
    id: int
    uuid_key: str
    email: str
    phone_number: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
