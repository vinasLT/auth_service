from pydantic import BaseModel

from database.schemas.role import RoleReadWithPermissions
from database.schemas.user import UserRead


class FullUserOut(UserRead):
    roles: list[RoleReadWithPermissions] = []


class UserWithRolePermission(UserRead):
    roles: list[str] = []
    permissions: list[str] = []


class Plan(BaseModel):
    max_bid_one_time: int
    name: str
    description: str
    bid_power: int
    price: int

class UserAccount(BaseModel):
    balance: int
    plan: Plan


class DetailedUser(UserWithRolePermission):
    account: UserAccount


