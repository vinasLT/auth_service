import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from core.logger import logger
from database.db.session import engine
from database.models import Permission, Role, RolePermission


def _coerce_bool_series(series: pd.Series) -> pd.Series:
    true_vals = {"1", "true", "t", "yes", "y"}
    false_vals = {"0", "false", "f", "no", "n"}

    def to_bool(x):
        if isinstance(x, bool):
            return x
        if pd.isna(x):
            return False
        s = str(x).strip().lower()
        if s in true_vals:
            return True
        if s in false_vals:
            return False
        try:
            return bool(int(s))
        except Exception:
            return s not in ("", "0", "false", "none", "nan")

    return series.map(to_bool)


def _optional_str(value) -> str | None:
    if pd.isna(value):
        return None
    return str(value)


def seed_db(db_engine: Engine):
    src_dir = CURRENT_FILE.parent / 'src'
    permission_df = pd.read_csv(src_dir / 'permission.csv')
    role_df = pd.read_csv(src_dir / 'role.csv')
    role_permissions_df = pd.read_csv(src_dir / 'role_permissions.csv')

    if 'is_default' in role_df.columns:
        role_df['is_default'] = _coerce_bool_series(role_df['is_default'])

    with Session(db_engine) as session, session.begin():
        csv_permission_id_to_db: dict[int, Permission] = {}
        for row in permission_df.itertuples(index=False):
            permission = session.scalar(
                select(Permission).where(
                    Permission.resource == row.resource,
                    Permission.action == row.action,
                )
            )
            if permission is None:
                permission = Permission(
                    name=row.name,
                    description=_optional_str(row.description),
                    resource=row.resource,
                    action=row.action,
                )
                session.add(permission)
                session.flush()
                logger.info(f"Created permission {row.resource}:{row.action}")
            csv_permission_id_to_db[int(row.id)] = permission

        csv_role_id_to_db: dict[int, Role] = {}
        for row in role_df.itertuples(index=False):
            role = session.scalar(select(Role).where(Role.name == row.name))
            if role is None:
                role = Role(
                    name=row.name,
                    is_default=bool(row.is_default) if hasattr(row, 'is_default') else False,
                    description=_optional_str(row.description),
                )
                session.add(role)
                session.flush()
                logger.info(f"Created role '{row.name}'")
            csv_role_id_to_db[int(row.id)] = role

        for row in role_permissions_df.itertuples(index=False):
            role = csv_role_id_to_db.get(int(row.role_id))
            permission = csv_permission_id_to_db.get(int(row.permission_id))
            if role is None:
                logger.warning(f"Role CSV id {row.role_id} not found, skipping role_permission")
                continue
            if permission is None:
                logger.warning(
                    f"Permission CSV id {row.permission_id} not found, skipping role_permission"
                )
                continue

            linked = session.scalar(
                select(RolePermission.id).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission.id,
                )
            )
            if linked is None:
                session.add(RolePermission(role_id=role.id, permission_id=permission.id))
                logger.info(
                    f"Granted {permission.resource}:{permission.action} to role '{role.name}'"
                )


if __name__ == '__main__':
    seed_db(engine)
