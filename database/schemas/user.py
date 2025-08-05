from pydantic import BaseModel, EmailStr, Field, field_validator, StringConstraints, ConfigDict
from typing import List, Optional, Annotated
from datetime import datetime
import re


PasswordStr = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=32,
        pattern=r"^\S+$"
    )
]

class UserIn(BaseModel):
    email: EmailStr = Field(
        ...,
        description="User email address",
        json_schema_extra={"example": "user@example.com"}
    )
    phone_number: str = Field(
        ...,
        description="User phone number",
        json_schema_extra={"example": "+1234567890"}
    )
    password: PasswordStr = Field(
        ...,
        description="Password must be 8-32 chars, include upper, lower, digit, special, no spaces",
        json_schema_extra={"example": "Str0ng!Pass1"}
    )

    @field_validator('phone_number')
    @classmethod
    def phone_e164(cls, v: str) -> str:
        v = re.sub(r'[\s\-\(\)]', '', v)
        if v.startswith('00'):
            v = '+' + v[2:]
        if not v.startswith('+') and v.isdigit():
            v = '+' + v
        assert re.fullmatch(r'\+[1-9]\d{7,14}', v), 'Invalid phone number format (E.164, e.g., +1234567890)'
        return v

    @field_validator('password')
    @classmethod
    def password_complexity(cls, v):
        assert not any(c.isspace() for c in v), 'Password must not contain spaces'
        assert re.search(r'[a-z]', v), 'Password must include at least one lowercase letter'
        assert re.search(r'[A-Z]', v), 'Password must include at least one uppercase letter'
        assert re.search(r'\d', v), 'Password must include at least one digit'
        assert re.search(r'[^A-Za-z0-9]', v), 'Password must include at least one special character'
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                'phone_number': '+1234567890',
                "password": "Str0ng!Pass1"
            }
        }
    )

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



class UserLogin(BaseModel):
    email: EmailStr = Field(...,
                            description='User email address',
                            json_schema_extra={"example": 'test@mail.com'})
    password: str = Field(...,
                          description='Password must be 8-32 chars, include upper, lower, digit, special, no spaces',
                          json_schema_extra={"example": 'Str0ng!Pass1'})









class TokenResponse(BaseModel):
    access_token: str = Field(..., description='Access JWT token', json_schema_extra={"example": "Bearer <KEY>"})
    refresh_token: str = Field(..., description='Refresh JWT token', json_schema_extra={"example": "Bearer <KEY>"})






