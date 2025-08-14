from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional
from datetime import datetime

from redis.commands.search.querystring import BaseNode


class UserCreate(BaseModel):
    uuid_key: str
    password_hash: str
    first_name: str
    last_name: str
    language: str = "en"
    phone_verified: Optional[bool] = False
    email_verified: Optional[bool] = False
    email: EmailStr
    username: str
    phone_number: str

class UserUpdate(BaseModel):
    phone_verified: Optional[bool] = False
    email_verified: Optional[bool] = False
    password_hash: Optional[str] = None

class UserRead(BaseModel):
    id: int
    uuid_key: str
    email: str
    phone_number: str
    is_active: bool
    first_name: str
    last_name: str
    language: str
    email_verified: bool
    phone_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
