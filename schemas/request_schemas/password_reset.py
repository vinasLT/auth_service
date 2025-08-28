from pydantic import Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from schemas.request_schemas.registration import EmailIn
from schemas.request_schemas.validators.password import password_complexity_validator
from schemas.request_schemas.verification_code import CodeIn


class ResetPasswordIn(EmailIn, CodeIn):
    new_password1: str = Field(
        ...,
        description="Password must be 8-32 chars, include upper, lower, digit, special, no spaces",
        json_schema_extra={"example": "Str0ng!Pass1"}
    )
    new_password2: str = Field(
        ...,
        description="Password must be 8-32 chars, include upper, lower, digit, special, no spaces",
        json_schema_extra={"example": "Str0ng!Pass1"}
    )

    @field_validator('new_password1', 'new_password2')
    @classmethod
    def password_complexity(cls, v):
        return password_complexity_validator(v)

    @model_validator(mode='before')
    @classmethod
    def passwords_match(cls, values):
        if values.get('new_password1') != values.get('new_password2'):
            raise PydanticCustomError('passwords_doesnt_match', 'Passwords do not match')
        return values

