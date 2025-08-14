import re

from pydantic_core import PydanticCustomError


def password_complexity_validator(password: str)-> str:
    if any(c.isspace() for c in password):
        raise PydanticCustomError('password_spaces', 'Password must not contain spaces')
    if not re.search(r'[a-z]', password):
        raise PydanticCustomError('password_lowercase', 'Password must include at least one lowercase letter')
    if not re.search(r'[A-Z]', password):
        raise PydanticCustomError('password_uppercase', 'Password must include at least one uppercase letter')
    if not re.search(r'\d', password):
        raise PydanticCustomError('password_digit', 'Password must include at least one digit')
    if not re.search(r'[^A-Za-z0-9]', password):
        raise PydanticCustomError('password_special', 'Password must include at least one special character')
    return password