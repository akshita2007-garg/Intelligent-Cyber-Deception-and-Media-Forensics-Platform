"""Database models (SQLAlchemy 2). SQLite by default, PostgreSQL via DATABASE_URL."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine,
                        event, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from . import config


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


engine = create_engine(
    config.DATABASE_URL,
    connect_args={"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {},
)

if config.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _):  # pragma: no cover
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    pw_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), default="investigator")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="case", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(String(512))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))            # hash at acquisition
    md5: Mapped[str] = mapped_column(String(32))
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    integrity_ok: Mapped[bool] = mapped_column(Boolean, default=True)
    module: Mapped[str] = mapped_column(String(32), default="unknown")
    status: Mapped[str] = mapped_column(String(32), default="pending")   # pending|analyzed|error
    uploaded_by: Mapped[str] = mapped_column(String(64))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    analysis_json: Mapped[str] = mapped_column(Text, default="{}")
    analysis_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str] = mapped_column(Text, default="")
    case: Mapped[Case] = relationship(back_populates="evidence")

    @property
    def analysis(self) -> dict:
        try:
            return json.loads(self.analysis_json or "{}")
        except json.JSONDecodeError:
            return {}


class Honeytoken(Base):
    __tablename__ = "honeytokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    token_type: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(200))
    value: Mapped[str] = mapped_column(String(512))
    secret: Mapped[str] = mapped_column(String(256), default="")
    placed_at: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DeceptionEvent(Base):
    """Interactions captured live by the built-in decoys (canary URLs, decoy admin portal)."""
    __tablename__ = "deception_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    decoy: Mapped[str] = mapped_column(String(64))
    src_ip: Mapped[str] = mapped_column(String(64))
    user_agent: Mapped[str] = mapped_column(String(512), default="")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    honeytoken_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    """Hash-chained chain-of-custody log: each entry commits to the previous entry's hash."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


def _entry_digest(prev: str, case_id, actor, action, detail, ts: datetime) -> str:
    payload = json.dumps([prev, case_id, actor, action, detail, ts.isoformat()], sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def audit(db: Session, actor: str, action: str, detail: str = "", case_id: int | None = None) -> AuditLog:
    last = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one_or_none()
    prev = last.entry_hash if last else "0" * 64
    ts = utcnow()
    entry = AuditLog(case_id=case_id, actor=actor, action=action, detail=detail, ts=ts,
                     prev_hash=prev, entry_hash=_entry_digest(prev, case_id, actor, action, detail, ts))
    db.add(entry)
    db.flush()
    return entry


def verify_audit_chain(db: Session) -> tuple[bool, int | None]:
    """Returns (ok, first_bad_id)."""
    prev = "0" * 64
    for e in db.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
        if e.prev_hash != prev or e.entry_hash != _entry_digest(prev, e.case_id, e.actor, e.action, e.detail, e.ts):
            return False, e.id
        prev = e.entry_hash
    return True, None


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
