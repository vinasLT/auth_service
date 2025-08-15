import re
from typing import Annotated

from pydantic import StringConstraints, BaseModel, EmailStr, Field, field_validator

from request_schemas.validators.email import validate_email
from request_schemas.validators.password import password_complexity_validator

PasswordStr = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=32,
        pattern=r"^\S+$"
    )
]

class EmailIn(BaseModel):
    email: EmailStr = Field(
        ...,
        description="User email address",
        json_schema_extra={"example": "user@example.com"}
    )

    @field_validator('email')
    @classmethod
    def validate_email_ascii(cls, v):
        return validate_email(v)

class PasswordIn(BaseModel):
    password: PasswordStr = Field(
        ...,
        description="Password must be 8-32 chars, include upper, lower, digit, special, no spaces",
        json_schema_extra={"example": "Str0ng!Pass1"}
    )

    @field_validator('password')
    @classmethod
    def password_complexity(cls, v):
        return password_complexity_validator(v)



class EmailPassIn(EmailIn, PasswordIn):
    pass



class UserIn(EmailPassIn):
    phone_number: str = Field(
        ...,
        description="User phone number",
        json_schema_extra={"example": "+1234567890"}
    )

    @field_validator('phone_number')
    @classmethod
    def phone_e164(cls, v: str) -> str:
        v = v.lower()
        v = re.split(r'(x|ext\.|#)', v)[0]
        v = re.sub(r'[^\d]', '', v)
        if v.startswith('00'):
            v = v[2:]

        assert re.fullmatch(r'[1-9]\d{6,14}', v), 'Invalid phone number format (7-15 digits, e.g., 1234567890)'

        return v

    first_name: str = Field(
        ...,
        description="User first name",
        json_schema_extra={"example": "John"},

        min_length=1,
        max_length=32,
    )

    last_name: str = Field(
        ...,
        description="User last name",
        json_schema_extra={"example": "Doe"},
        min_length=1,
        max_length=32,
    )
