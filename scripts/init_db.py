import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from sqlalchemy import Engine, text
from database.db.session import engine
from core.logger import logger


def _coerce_bool_series(series: pd.Series) -> pd.Series:
    """Coerce a pandas Series with values like 0/1, "0"/"1", "true"/"false" to booleans."""
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


def seed_db(engine: Engine):
    src_dir = CURRENT_FILE.parent / 'src'

    tables = {
        'permission': src_dir / 'permission.csv',
        'role': src_dir / 'role.csv',
        'role_permissions': src_dir / 'role_permissions.csv',

    }

    # Deletion order: children first, then parents (to satisfy FKs)
    delete_order = [
        'role',
        'permission',
        'role_permissions',
    ]

    # Insertion order: parents first, then children
    insert_order = [
        'role',
        'permission',
        'role_permissions'
    ]

    # Phase 1: delete existing data without dropping tables (preserve schema & FKs)
    with engine.begin() as conn:
        for table in delete_order:
            logger.info(f'Clearing table {table}')
            try:
                conn.execute(text(f'DELETE FROM "{table}"'))
            except Exception as e:
                logger.warning(f'Failed to delete from {table}: {e}')

    # Phase 2: insert data
    for table in insert_order:
        path = tables[table]
        logger.info(f'Seeding table {table} from {path}')
        df = pd.read_csv(path)
        if table == 'destination' and 'is_default' in df.columns:
            df['is_default'] = _coerce_bool_series(df['is_default'])
        df.to_sql(table, engine, if_exists='replace', index=False)


if __name__ == '__main__':
    seed_db(engine)
