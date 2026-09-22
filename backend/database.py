from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from settings import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def migrate_legacy_schema() -> None:
    """Apply safe additive migrations for existing local SQLite databases."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    
    # 1. Update encryption_records columns if table exists
    if "encryption_records" in existing_tables:
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

    # 2. Update users columns if table exists
    if "users" in existing_tables:
        columns = {c["name"] for c in inspector.get_columns("users")}
        if "retention_days" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN retention_days INTEGER DEFAULT 30"))

    # 3. Update scans columns if table exists
    if "scans" in existing_tables:
        columns = {c["name"] for c in inspector.get_columns("scans")}
        if "is_quarantined" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN is_quarantined BOOLEAN DEFAULT 0"))
        if "quarantine_reason" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN quarantine_reason VARCHAR(255) DEFAULT ''"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
