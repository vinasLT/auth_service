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
    if db_engine.dialect.name != "postgresql":
        logger.info("Skipping sequence reset for non-PostgreSQL dialect")
        return
    sql = """
DO $$
DECLARE
  r record;
  max_id bigint;
  seq_reg regclass;
  seq_schema text;
  seq_name text;
  startv bigint;
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
    WHERE c.relkind IN ('r','p')
      AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
  LOOP
    IF r.seq IS NOT NULL THEN
      seq_reg := r.seq::regclass;
      SELECT ns.nspname, cl.relname
      INTO seq_schema, seq_name
      FROM pg_class cl
      JOIN pg_namespace ns ON ns.oid = cl.relnamespace
      WHERE cl.oid = seq_reg;

      SELECT start_value
      INTO startv
      FROM pg_sequences
      WHERE schemaname = seq_schema AND sequencename = seq_name;

      EXECUTE format('SELECT MAX(%I) FROM %I.%I', r.col, r.sch, r.tbl) INTO max_id;

      IF max_id IS NULL THEN
        EXECUTE format('SELECT setval(%L, %s, false)', r.seq, startv);
      ELSE
        EXECUTE format('SELECT setval(%L, %s, true)', r.seq, max_id);
      END IF;
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
