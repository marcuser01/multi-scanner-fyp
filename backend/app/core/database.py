from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from app.models.database import Base

# Added pool configuration & timeouts to handle concurrent traffic spikes safely
engine = create_engine(
    settings.DATABASE_URL, 
    connect_args={"check_same_thread": False, "timeout": 30},
    pool_size=10,         # Keeps 10 connections warm and ready
    max_overflow=20       # Allows up to 20 temporary burst connections
)

# SQLite Concurrency optimization: Enable WAL mode for simultaneous reads/writes
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL") 
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    # Creates the actual database tables based on structural definitions
    Base.metadata.create_all(bind=engine)