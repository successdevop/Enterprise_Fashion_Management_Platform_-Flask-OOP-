from datetime import datetime
from uuid import UUID

from sqlalchemy import Column, DateTime, Index
from sqlmodel import SQLModel, Field

from app.schemas.email.enums import EmailVerificationStatus
from base_models.base_models import UUIDPrimaryKeyMixin


class EmailVerification(UUIDPrimaryKeyMixin, SQLModel, table=True):
    __tablename__ = "email_verification"

    user_id: UUID = Field(
        foreign_key="user.id",
        nullable=False,
        index=True
    )

    email: str = Field(
        nullable=False,
        index=True,
    )

    token_hash: str = Field(
        nullable=False,
        unique=True,
        index=True
    )

    status: EmailVerificationStatus = Field(
        default=EmailVerificationStatus.PENDING,
        index=True,
        nullable=False
    )

    expires_at: datetime = Field(
        nullable=False,
        index=True
    )

    sent_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True)
    )

    invalidated_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True)
    )

    delivery_attempts: int = Field(
        default=0,
        max_length=100
    )

    __table_args__ = (
        Index("idx_email_verification_user_status", "user_id", "status")
    )