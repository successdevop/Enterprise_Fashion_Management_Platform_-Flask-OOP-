from datetime import datetime
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.enums.email import EmailVerificationStatus
from email.email import EmailVerification


class EmailRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_token_hash(self, token: str) -> EmailVerification | None:
        stmt = select(EmailVerification).where(
            EmailVerification.token_hash == token
        )

        result = await self._session.exec(stmt)
        return result.first()

    async def get_active_for_user(self, user_id: UUID) -> EmailVerification | None:
        stmt = select(EmailVerification).where(
            EmailVerification.user_id == user_id,
            EmailVerification.status.is_(
                [
                    EmailVerificationStatus.PENDING,
                    EmailVerificationStatus.SENT,
                ]
            )
        ).order_by(
            EmailVerification.created_at.desc()
        )

        result = (await self._session.exec(stmt))
        return result.first()

    async def invalidate_active_for_user(self, user_id: UUID, invalidated_at: datetime) -> None:
        from sqlmodel import update

        stmt = update(EmailVerification).where(
            EmailVerification.user_id == user_id,       #type: ignore
            EmailVerification.status.is_(                            #type: ignore
                [
                    EmailVerificationStatus.PENDING,
                    EmailVerificationStatus.SENT
                ]
            )
        ).values(
            status=EmailVerificationStatus.SUPERSEDED,
            invalidated_at=invalidated_at
        )

        (await self._session.exec(stmt))

    async def add_and_flush(self, verification: EmailVerification) -> EmailVerification:
        verification_dict = verification.model_dump()

        new_verification = EmailVerification(
            **verification_dict
        )

        self._session.add(new_verification)
        await self._session.flush()

        return new_verification

