"""SQLAlchemy engine + session factory for SQLite."""
import logging
import os

from sqlalchemy import create_engine, inspect as sa_inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///../data/qready.db")

# check_same_thread=False is required for SQLite in FastAPI
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — yields a database session and closes it on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables() -> None:
    """Create all tables that have not been created yet. Called on startup."""
    import orm  # noqa: F401 — import triggers model registration
    Base.metadata.create_all(bind=engine)
    _migrate_schema()
    logger.info(
        "Database tables created / verified at %s",
        engine.url.render_as_string(hide_password=True),
    )


def _migrate_schema() -> None:
    """
    Add columns present in ORM models but missing from an existing database.

    Uses SQLAlchemy's inspector to compare the live schema against the ORM
    metadata and issues ALTER TABLE … ADD COLUMN for each gap found.
    All missing columns are added as nullable in SQLite DDL so that existing
    rows are not rejected; SQLAlchemy fills in Python-side defaults on new
    inserts as usual.
    """
    inspector = sa_inspect(engine)
    with engine.connect() as conn:
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing_cols = {col["name"] for col in inspector.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing_cols:
                    continue
                col_type = col.type.compile(dialect=engine.dialect)
                try:
                    conn.execute(
                        text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {col_type}')
                    )
                    logger.info("_migrate_schema: added column %s.%s", table.name, col.name)
                except Exception as exc:
                    logger.warning(
                        "_migrate_schema: could not add %s.%s: %s", table.name, col.name, exc
                    )
        conn.commit()
