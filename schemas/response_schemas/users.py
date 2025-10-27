from database.schemas.role import RoleReadWithPermissions
from database.schemas.user import UserRead


class FullUserOut(UserRead):
    roles: list[RoleReadWithPermissions] = []


class UserWithRolePermission(UserRead):
    roles: list[str] = []
    permissions: list[str] = []

