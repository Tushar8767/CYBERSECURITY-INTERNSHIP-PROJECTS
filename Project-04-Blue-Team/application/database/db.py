from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from config.settings import settings
from database.orm_models import Base


def make_engine(db_path: Path | None = None):
    path = db_path or settings.root_dir / settings.database_path
    return create_engine(f"sqlite:///{path}", future=True)


engine = make_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def init_db() -> None:
    Base.metadata.create_all(engine)
