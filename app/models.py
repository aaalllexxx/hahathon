from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    gitlab_project_id: Mapped[int | None] = mapped_column(Integer, index=True)
    url: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    checks: Mapped[list["SecurityCheck"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
    )


class SecurityCheck(Base):
    __tablename__ = "security_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, index=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    author: Mapped[str | None] = mapped_column(String(255))
    commit_sha: Mapped[str | None] = mapped_column(String(128), index=True)
    branch: Mapped[str | None] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True, default="passed")
    severity: Mapped[str] = mapped_column(String(32), index=True, default="LOW")
    summary: Mapped[str | None] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(String(32), index=True, default="webhook")
    enforcement: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    repository: Mapped[Repository] = relationship(back_populates="checks")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="check",
        cascade="all, delete-orphan",
        order_by="Finding.id",
    )
    messages: Mapped[list["BotMessage"]] = relationship(
        back_populates="check",
        cascade="all, delete-orphan",
        order_by="BotMessage.created_at",
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("security_checks.id"), index=True)
    cwe: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    file: Mapped[str | None] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer)
    code: Mapped[str | None] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    fix: Mapped[str | None] = mapped_column(Text)
    fixed_example: Mapped[str | None] = mapped_column(Text)
    llm_verdict: Mapped[str | None] = mapped_column(String(32))
    llm_confidence: Mapped[float | None] = mapped_column(Float)

    check: Mapped[SecurityCheck] = relationship(back_populates="findings")

    @property
    def inline_comment(self) -> str:
        from app.scanner.annotations import build_inline_comment

        return build_inline_comment(self)

    @property
    def annotated_code(self) -> str:
        from app.scanner.annotations import annotate_vulnerable_line

        return annotate_vulnerable_line(self.code or "", self.file or "", self)


class BotMessage(Base):
    __tablename__ = "bot_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("security_checks.id"), index=True)
    role: Mapped[str] = mapped_column(String(32), index=True)
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    check: Mapped[SecurityCheck] = relationship(back_populates="messages")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    level: Mapped[str] = mapped_column(String(32), index=True, default="INFO")
    event: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str | None] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
