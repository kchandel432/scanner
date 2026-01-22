from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.core.settings import settings
from backend.domain.schemas.database import Base
import os

db_url = settings.DATABASE_URL or 'sqlite:///./instance/blacklotus.db'
# Ensure the instance directory exists
import os
os.makedirs(os.path.dirname(db_url.replace('sqlite:///', '')), exist_ok=True)
connect_args = {"check_same_thread": False} if db_url.startswith('sqlite') else {}

engine = create_engine(db_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database (create tables)."""
    Base.metadata.create_all(bind=engine)
