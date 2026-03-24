import logging
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from .config import get_settings

logger = logging.getLogger(__name__)

engine = create_engine(
    get_settings().database_url,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create tables and add any missing columns to existing tables.

    SQLAlchemy's create_all() only creates new tables — it does NOT
    add columns to existing tables.  This function inspects the DB
    and issues ALTER TABLE for any columns defined in the models but
    missing from the actual schema.
    """
    Base.metadata.create_all(bind=engine)
    _migrate_missing_columns()


# Map of SQLAlchemy type names to SQLite column types
_TYPE_MAP = {
    "VARCHAR": "VARCHAR",
    "TEXT": "TEXT",
    "INTEGER": "INTEGER",
    "BOOLEAN": "BOOLEAN",
    "FLOAT": "FLOAT",
    "DATETIME": "DATETIME",
    "JSON": "JSON",
}


def _sa_type_to_sqlite(sa_type) -> str:
    type_name = type(sa_type).__name__.upper()
    return _TYPE_MAP.get(type_name, "TEXT")


def _migrate_missing_columns():
    """Add columns that exist in models but not yet in the database."""
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    for table_name, table in Base.metadata.tables.items():
        if table_name not in existing_tables:
            continue

        existing_cols = {col["name"] for col in inspector.get_columns(table_name)}

        for column in table.columns:
            if column.name in existing_cols:
                continue

            col_type = _sa_type_to_sqlite(column.type)

            # Determine default value for the ALTER TABLE statement
            default = "NULL"
            if column.default is not None:
                arg = column.default.arg
                if callable(arg):
                    # e.g. default=list or default=dict
                    default = "'[]'" if arg in (list,) else "'{}'"
                elif isinstance(arg, str):
                    default = f"'{arg}'"
                elif isinstance(arg, bool):
                    default = "1" if arg else "0"
                elif isinstance(arg, (int, float)):
                    default = str(arg)

            sql = f"ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type} DEFAULT {default}"
            logger.info("Migration: %s", sql)

            with engine.begin() as conn:
                conn.execute(text(sql))
