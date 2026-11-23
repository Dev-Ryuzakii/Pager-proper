"""Add tables and columns the models define but the database lacks.

For restoring a database made by an older version of the backend: creates
missing tables, then adds each missing column as nullable (with its server
default, if any). Never drops or changes anything.

    python schema_sync.py           # show what is missing
    python schema_sync.py --apply   # add it
"""
import os
import sys

from sqlalchemy import create_engine, inspect, text

import fastapi_mobile_backend_postgresql  # noqa: F401  registers every model on Base
from database_models import Base


def main(apply: bool) -> int:
    engine = create_engine(os.environ["DATABASE_URL"])
    insp = inspect(engine)
    existing = set(insp.get_table_names())
    missing_tables = [t for t in Base.metadata.sorted_tables if t.name not in existing]
    for t in missing_tables:
        print(f"table  {t.name}")
    if apply and missing_tables:
        Base.metadata.create_all(bind=engine, tables=missing_tables)

    statements = []
    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            ddl = f'ALTER TABLE "{table.name}" ADD COLUMN IF NOT EXISTS "{col.name}" {col.type.compile(dialect=engine.dialect)}'
            if col.server_default is not None and hasattr(col.server_default, "arg"):
                arg = col.server_default.arg
                ddl += f" DEFAULT {arg.text if hasattr(arg, 'text') else repr(arg)}"
            print(f"column {table.name}.{col.name}")
            statements.append(ddl)

    if apply and statements:
        with engine.begin() as conn:
            for ddl in statements:
                conn.execute(text(ddl))
    if not missing_tables and not statements:
        print("schema up to date")
    elif not apply:
        print("dry run: re-run with --apply to add these")
    return 0


if __name__ == "__main__":
    sys.exit(main("--apply" in sys.argv))
