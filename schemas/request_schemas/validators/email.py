import re

from pydantic_core import PydanticCustomError


def validate_email(v) -> str:
    if not re.match(r'^[\x00-\x7F]+$', v):
        raise PydanticCustomError('invalid_email_address',
                                  'Invalid email address')
    return v.lower()