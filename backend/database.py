from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from settings import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def migrate_legacy_schema() -> None:
    """Apply small additive migrations for existing local SQLite databases."""
    inspector = inspect(engine)
    if "encryption_records" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("encryption_records")}
        additions = {
            "sha256": "VARCHAR(64) DEFAULT ''",
            "operation": "VARCHAR(12) DEFAULT 'encrypt'",
            "stored_name": "VARCHAR(64) DEFAULT ''",
            "original_sha256": "VARCHAR(64) DEFAULT ''",
        }
        missing = [(name, definition) for name, definition in additions.items() if name not in columns]
        if missing:
            with engine.begin() as conn:
                for name, definition in missing:
                    conn.execute(text(f"ALTER TABLE encryption_records ADD COLUMN {name} {definition}"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
