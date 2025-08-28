from typing import Optional

from pydantic import BaseModel, Field


class UserSearchIn(BaseModel):
    search: Optional[str] = Field('', description='Search by email, first, last names, phone_number etc.')
    include_inactive: bool = Field(False, description='Include users who are not active')