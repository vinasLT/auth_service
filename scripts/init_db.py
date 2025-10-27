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


def reset_all_sequences(db_engine: Engine):
    sql = """
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT
      n.nspname AS sch,
      c.relname AS tbl,
      a.attname AS col,
      pg_get_serial_sequence(format('%I.%I', n.nspname, c.relname), a.attname) AS seq
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
    WHERE c.relkind IN ('r','p')
      AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
      AND pg_get_expr(d.adbin, d.adrelid) LIKE 'nextval(%'
  LOOP
    IF r.seq IS NOT NULL THEN
      EXECUTE format(
        'SELECT setval(%L, COALESCE((SELECT MAX(%I) FROM %I.%I), 0))',
        r.seq, r.col, r.sch, r.tbl
      );
    END IF;
  END LOOP;
END $$;
"""
    with db_engine.begin() as conn:
        conn.execute(text(sql))


def seed_db(db_engine: Engine):
    src_dir = CURRENT_FILE.parent / 'src'

    tables = {
        'permission': src_dir / 'permission.csv',
        'role': src_dir / 'role.csv',
        'role_permissions': src_dir / 'role_permissions.csv',
    }

    delete_order = [
        'role_permissions',
        'role',
        'permission',
    ]

    insert_order = [
        'permission',
        'role',
        'role_permissions'
    ]

    with db_engine.begin() as conn:
        for table in delete_order:
            logger.info(f'Clearing table {table}')
            try:
                conn.execute(text(f'DELETE FROM "{table}"'))
            except Exception as e:
                logger.warning(f'Failed to delete from {table}: {e}')

    for table in insert_order:
        path = tables[table]
        logger.info(f'Seeding table {table} from {path}')
        df = pd.read_csv(path)
        if df.empty:
            logger.warning(f'Skipping {table}: CSV is empty')
            continue
        if table == 'role' and 'is_default' in df.columns:
            df['is_default'] = _coerce_bool_series(df['is_default'])
        df.to_sql(table, db_engine, if_exists='append', index=False)

    logger.info('Resetting all sequences to match current max ids')
    reset_all_sequences(db_engine)


if __name__ == '__main__':
    seed_db(engine)
