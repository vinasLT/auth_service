from pydantic import Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from request_schemas.registration import EmailIn, PasswordIn, PasswordStr
from request_schemas.validators.password import password_complexity_validator
from request_schemas.verification_code import CodeIn


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
    def passwords_match(self):
        if self.new_password1 != self.new_password2:
            raise PydanticCustomError('passwords_doesnt_match','Passwords do not match')
        return self