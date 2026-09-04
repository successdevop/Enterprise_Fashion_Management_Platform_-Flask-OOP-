from datetime import datetime, date, timezone
from uuid import UUID, uuid4

from sqlmodel import SQLModel, Field
import sqlalchemy as sa

from app.enums.org_enums import StaffAssignmentStatus
from app.enums.user_enums import GenderEnum


class UUIDPrimaryKeyMixin(SQLModel):
    id: UUID = Field(
        default_factory=uuid4,
        primary_key=True
    )


class UserInfoMixin(SQLModel):
    first_name: str | None = None
    last_name: str | None = None
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)
    phone_number: str = Field(unique=True, index=True)
    avatar_url: str | None = None
    gender: GenderEnum | None = None
    date_of_birth: date | None = None
    is_active: bool = Field(default=False, index=True)
    is_email_verified: bool = False
    is_phone_verified: bool = False
    password_hash: str


class StaffAssignmentMixin(SQLModel):
    assigned_at: datetime = Field(
        default_factory=lambda : datetime.now(timezone.utc),
        sa_type=sa.DateTime(timezone=True) # type: ignore
    )

    removed_at: datetime | None = Field(
        default=None,
        sa_type=sa.DateTime(timezone=True), # type: ignore
    )

    assigned_by: UUID
    removed_by: UUID | None = None
    status: StaffAssignmentStatus


class SoftDeleteMixin(SQLModel):
    is_deleted: bool = Field(
        default=False,
        index=True
    )
    deleted_at: datetime | None = Field(
        default=None,
        sa_type=sa.DateTime(timezone=True), # type: ignore
    )
    deleted_by: UUID | None = None


class TimestampMixin(SQLModel):
    created_at: datetime = Field(
        default_factory=lambda : datetime.now(timezone.utc),
        sa_type=sa.DateTime(timezone=True), # type: ignore
        nullable=False,
        index=True
    )

    updated_at: datetime | None = Field(
        default=None,
        sa_type=sa.DateTime(timezone=True), # type: ignore
        nullable=True,
        index=True
    )
