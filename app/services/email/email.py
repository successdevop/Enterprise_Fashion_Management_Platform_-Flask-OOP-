from datetime import datetime, timezone, timedelta
from uuid import UUID

from app.config.config import verification_settings
from app.enums.email import EmailVerificationStatus
from app.exceptions.exceptions import UserNotFoundError
from app.repositories.outbox import OutboxRepository
from app.repositories.user_repo import UserRepository
from app.security.repository.email.email import EmailRepository
from app.utils.auth import generate_url_safe_token, hash_function
from app.models.email.email import EmailVerification


class EmailService:
    def __init__(self, verification_repo: EmailRepository, user_repo: UserRepository, outbox_repo: OutboxRepository) -> None:
        self._verification_repo = verification_repo
        self._user_repo = user_repo
        self._outbox_repo = outbox_repo

    async def create_verification(self, user_id: UUID) -> str:
        now = datetime.now(tz=timezone.utc)

        user = await self._user_repo.get_by_id(uid=user_id)
        if not user:
            raise UserNotFoundError()

        if user.email_verified:
            return

        await self._verification_repo.invalidate_active_for_user(
            user_id=user_id,
            invalidated_at=now
        )

        new_token = generate_url_safe_token()

        hash_token = hash_function(hashable=new_token)

        new_verification = EmailVerification(
            user_id=user_id,
            email=user.email,
            token_hash=hash_token,
            status=EmailVerificationStatus.PENDING,
            expires_at=now + timedelta(minutes=verification_settings.EMAIL_VERIFICATION_TOKEN_TTL_MINUTES)
        )

        await self._verification_repo.add_and_flush(verification=new_verification)

        await self._outbox_repo.add_and_flush(
            event_type="email.verification",
            payload={
                "verification_id": str(new_verification.id),
                "user_id": str(user.id),
                "token": new_token
            }
        )

        return new_token

