from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.core.config import settings
from backend.domain.schemas.database import Base
import os

db_url = getattr(settings, 'database_url', 'sqlite:///./data/dev.db')
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
