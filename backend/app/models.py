from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Operation(Base):
    __tablename__ = "operations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    target_type: Mapped[str] = mapped_column(String(16))  # image | physical
    target_identifier: Mapped[str] = mapped_column(String(512))
    target_label: Mapped[str] = mapped_column(String(256))
    capacity_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    media_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    method: Mapped[str] = mapped_column(String(64))
    policy_level: Mapped[str] = mapped_column(String(16))  # clear | purge | destroy
    policy_reference: Mapped[str] = mapped_column(String(256))

    status: Mapped[str] = mapped_column(String(32), default="pending")
    verification_status: Mapped[str] = mapped_column(String(32), default="not_run")
    simulation_only: Mapped[bool] = mapped_column(default=False)

    operator_id: Mapped[str] = mapped_column(String(128))

    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    limitations: Mapped[list] = mapped_column(JSON, default=list)

    certificates: Mapped[list["Certificate"]] = relationship(back_populates="operation")


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    operation_id: Mapped[str] = mapped_column(ForeignKey("operations.id"))

    final_status: Mapped[str] = mapped_column(String(32))  # Verified|Failed|Inconclusive
    pdf_path: Mapped[str] = mapped_column(String(512))
    content_hash: Mapped[str] = mapped_column(String(128))
    signature_b64: Mapped[str | None] = mapped_column(Text, nullable=True)
    public_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signature_algorithm: Mapped[str] = mapped_column(String(64), default="none")

    issued_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    operation: Mapped[Operation] = relationship(back_populates="certificates")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    operation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(128))
    entry_hash: Mapped[str] = mapped_column(String(128))
