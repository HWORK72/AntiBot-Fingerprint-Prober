import datetime
import uuid
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from storage.db import Base


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    stealth_score: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict: Mapped[str] = mapped_column(String(100), nullable=False)
    total_penalties: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_triggers_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    ja3_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ja4_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    akamai_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)

    anomalies: Mapped[list["DetectedAnomalyRecord"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="selectin"
    )


class DetectedAnomalyRecord(Base):
    __tablename__ = "detected_anomalies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    penalty_score: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Text] = mapped_column(Text, nullable=False)
    recommendation: Mapped[Text] = mapped_column(Text, nullable=False)

    session: Mapped["ScanSession"] = relationship(back_populates="anomalies")