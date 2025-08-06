import re
from typing import Annotated

from pydantic import StringConstraints, BaseModel, EmailStr, Field, field_validator, ConfigDict

PasswordStr = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=32,
        pattern=r"^\S+$"
    )
]

class EmailPassIn(BaseModel):
    email: EmailStr = Field(
        ...,
        description="User email address",
        json_schema_extra={"example": "user@example.com"}
    )
    password: PasswordStr = Field(
        ...,
        description="Password must be 8-32 chars, include upper, lower, digit, special, no spaces",
        json_schema_extra={"example": "Str0ng!Pass1"}
    )

    @field_validator('password')
    @classmethod
    def password_complexity(cls, v):
        assert not any(c.isspace() for c in v), 'Password must not contain spaces'
        assert re.search(r'[a-z]', v), 'Password must include at least one lowercase letter'
        assert re.search(r'[A-Z]', v), 'Password must include at least one uppercase letter'
        assert re.search(r'\d', v), 'Password must include at least one digit'
        assert re.search(r'[^A-Za-z0-9]', v), 'Password must include at least one special character'
        return v

    @field_validator('email')
    @classmethod
    def validate_email_ascii(cls, v):
        assert re.match(r'^[\x00-\x7F]+$', v), 'Email must be ASCII only'
        return v

class UserIn(EmailPassIn):
    phone_number: str = Field(
        ...,
        description="User phone number",
        json_schema_extra={"example": "+1234567890"}
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

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                'phone_number': '+1234567890',
                "password": "Str0ng!Pass1"
            }
        }
    )