import os
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

DB_PATH = os.getenv(
    "NOGINX_DB_PATH",
    os.path.join(os.path.dirname(__file__), "..", "data", "noginx.db"),
)
DATABASE_URL = f"sqlite:///{os.path.abspath(DB_PATH)}"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incidents = relationship("Incident", back_populates="user")
    scans = relationship("ScanJob", back_populates="user")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    ip = Column(String(64), nullable=False)
    timestamp = Column(String(64), nullable=True)
    method = Column(String(16), nullable=True)
    path = Column(String(512), nullable=True)
    status = Column(Integer, nullable=True)
    threat_type = Column(String(128), nullable=False)
    confidence = Column(Float, nullable=False)
    severity = Column(String(32), nullable=False)
    user_agent = Column(Text, nullable=True)
    ml_score = Column(Float, nullable=True)
    raw_line = Column(Text, nullable=True)
    message = Column(Text, nullable=True)
    source = Column(String(32), default="dashboard")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="incidents")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    total_lines = Column(Integer, default=0)
    threats_found = Column(Integer, default=0)
    best_threat = Column(String(128), nullable=True)
    best_confidence = Column(Float, nullable=True)
    status = Column(String(32), default="completed")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="scans")


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    Base.metadata.create_all(bind=engine)
    _migrate_incident_columns()


def _migrate_incident_columns() -> None:
    with engine.begin() as conn:
        columns = {
            row[1]
            for row in conn.exec_driver_sql("PRAGMA table_info(incidents)").fetchall()
        }
        if "message" not in columns:
            conn.exec_driver_sql("ALTER TABLE incidents ADD COLUMN message TEXT")
        if "source" not in columns:
            conn.exec_driver_sql(
                "ALTER TABLE incidents ADD COLUMN source VARCHAR(32) DEFAULT 'dashboard'"
            )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
