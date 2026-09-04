from sqlmodel.ext.asyncio.session import AsyncSession

from app.repositories.audit import AuditLogRepository
from app.repositories.email import EmailRepository
from app.security.repository.auth_repo import AuthSessionRepository
from app.security.repository.refresh_repo import RefreshTokenRepository
from app.security.repository.security_repo import SecurityRepository
from app.transactions_mgt.base import UnitOfWork
from app.repositories.outbox import OutboxRepository
from app.repositories.user_repo import UserRepository


class AuthUnitOfWork(UnitOfWork):
    def __init__(self, session: AsyncSession):
        super().__init__(session=session)

        self.security_event = SecurityRepository(session=session)
        self.users = UserRepository(session=session)
        self.outbox_messages = OutboxRepository(session=session)
        self.audit_logs = AuditLogRepository(session=session)
        self.auth_sessions = AuthSessionRepository(session=session)
        self.refresh_tokens = RefreshTokenRepository(session=session)
        self.email = EmailRepository(session=session)