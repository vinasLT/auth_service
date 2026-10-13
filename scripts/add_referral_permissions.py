import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from core.logger import logger
from database.db.session import engine
from database.models import Permission, Role, RolePermission

REFERRAL_PERMISSIONS = [
    ("auth.referral.own", "read", "Read own referral stats", ["user"]),
    ("auth.referral.all", "read", "Read all referral stats", ["admin", "developer"]),
    ("auth.referral.all", "write", "Manage referral rewards", ["admin", "developer"]),
    ("payments.referral_wallet.own", "read", "Read own referral wallet", ["user"]),
    ("payments.referral_wallet.all", "read", "Read all referral wallets", ["admin", "developer"]),
    ("payments.referral_wallet.all", "write", "Manage referral wallets", ["admin", "developer"]),
]


def add_referral_permissions(db_engine: Engine) -> None:
    with Session(db_engine) as session, session.begin():
        for resource, action, description, role_names in REFERRAL_PERMISSIONS:
            permission = session.scalar(
                select(Permission).where(Permission.resource == resource, Permission.action == action)
            )
            if permission is None:
                permission = Permission(name=description, description=description, resource=resource, action=action)
                session.add(permission)
                session.flush()
                logger.info(f"Created permission {resource}:{action}")

            for role_name in role_names:
                role = session.scalar(select(Role).where(Role.name == role_name))
                if role is None:
                    logger.warning(f"Role '{role_name}' not found, skipping {resource}:{action}")
                    continue

                linked = session.scalar(
                    select(RolePermission.id).where(
                        RolePermission.role_id == role.id,
                        RolePermission.permission_id == permission.id,
                    )
                )
                if linked is None:
                    session.add(RolePermission(role_id=role.id, permission_id=permission.id))
                    logger.info(f"Granted {resource}:{action} to role '{role_name}'")


if __name__ == '__main__':
    add_referral_permissions(engine)
