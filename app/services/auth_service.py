import hmac
from datetime import datetime, timezone, timedelta
from uuid import uuid4, UUID

from sqlalchemy.exc import IntegrityError

from app.config.config import verification_settings
from app.enums.email import EmailVerificationStatus
from app.schemas.base_or_shared.audit import AuditLogCreate
from app.security.model.auth_session import AuthSession
from app.security.model.refresh_token import RefreshToken
from app.security.model.security_event import SecurityEvent
from app.security.service.passwd_policy import PasswordPolicy
from app.security.service.passwd_service import PasswordService
from app.security.service.token_service import TokenService
from app.transactions_mgt.auth import AuthUnitOfWork
from app.models import User
from app.schemas.identity.user import UserCreate, TokenResponse
from app.utils.auth import hash_refresh_token, generate_url_safe_token, hash_function
from app.exceptions.exceptions import (
    EmailAlreadyExistsError, UsernameAlreadyTakenError, PhoneNumberAlreadyExistsError, DatabaseIntegrityError,
    InvalidPasswordError, InvalidCredentialsError, InactiveAccountError, InvalidRefreshTokenError,
    RefreshTokenReuseDetected, InvalidAccessTokenError, EmailNotVerifiedError
)
from email.email import EmailVerification


class AuthService:
    def __init__(self, auth: AuthUnitOfWork, password_service: PasswordService, token_service: TokenService) -> None:
        self._authUoW = auth
        self._password_service = password_service
        self._token_service = token_service

    ## REGISTER USER
    async def register_user(self, user_data: UserCreate) -> User:
        # hash password
        password_hash = self._password_service.hash(password=user_data.password)

        # check if user already exist or still exists after activating deletion process
        existing_user = await self._authUoW.users.get_by_email_including_deleted(email=user_data.email)
        if existing_user:
            if existing_user.is_deleted and existing_user.deleted_at:

                # check how days the email has been deleted
                deletion_days = datetime.now(tz=timezone.utc) - existing_user.deleted_at
                if deletion_days <= timedelta(days=30):

                    # send an email informing the customer to activate their account by logging in
                    raise EmailAlreadyExistsError()

            # customer has an active account and doesn't need activation
            raise EmailAlreadyExistsError()

        # if user doesn't exist, check if chosen username already exists
        existing_username = await self._authUoW.users.get_by_username(username=user_data.username)
        if existing_username:
            raise UsernameAlreadyTakenError()

        # check if chosen phone number already exist
        existing_phone_number = await self._authUoW.users.get_by_phone_number(phone_number=user_data.phone_number)
        if existing_phone_number:
            raise PhoneNumberAlreadyExistsError()

        # exclude plain password from being passed to model
        user_dict = user_data.model_dump(exclude={"password"})

        # create new user
        new_user = User(
            **user_dict,
            password_hash=password_hash,
            is_active=True
        )

        try:

            # manage transaction using unit_of_work pattern to make registration atomic
            await self._authUoW.users.add_and_flush(new_user)

            # create email verification and outbox record
            await self._create_verification(user=new_user)

            # create audit record
            audit = {
                "actor_id": new_user.id, "audit_action":"USER_REGISTERED",
                "resource_type":"User", "resource_id":new_user.id
            }

            await self._authUoW.audit_logs.add_and_flush(
                audit_schema=AuditLogCreate(**audit)
            )

            # commit and return user
            await self._authUoW.commit()
            return new_user

        except IntegrityError as exc:
            await self._authUoW.rollback()

            raise DatabaseIntegrityError() from exc

        except Exception:
            await self._authUoW.rollback()
            raise

    ## LOGIN USER
    async def login_user(self, email: str, password: str):
        is_valid, message = PasswordPolicy.validate(password=password)
        if not is_valid:
            raise InvalidPasswordError(message)

        email = email.strip().lower()

        user = await self._authUoW.users.get_by_email_including_deleted(email=email)
        if not user:
            raise InvalidCredentialsError()

        if user and not self._password_service.verify(password=password, hashed=user.password_hash):
            raise InvalidCredentialsError()

        if user and not user.email_verified:
            raise EmailNotVerifiedError()

        if user:
            if not user.is_deleted and not user.is_active:
                raise InactiveAccountError()

            elif user.is_deleted and user.deleted_at:
                deletion_days = datetime.now(tz=timezone.utc) - user.deleted_at
                if deletion_days < timedelta(days=30):
                    user.is_deleted = False
                    user.deleted_at = None
                    user.is_active = True

        now = datetime.now(tz=timezone.utc)
        refresh_token_lifetime_in_days = timedelta(days=self._token_service.refresh_token_lifetime)

        refresh_token_id = uuid4()
        family_id = uuid4()

        session = AuthSession(
            user_id=user.id,
            family_token_id=family_id,
            expires_at=now + refresh_token_lifetime_in_days
        )

        try:
            await self._authUoW.auth_sessions.add_and_flush(auth_session=session)

            refresh_token = self._token_service.create_refresh_token(
                user_id=user.id,
                session_id=session.id,
                family_token_id=family_id,
                token_id=refresh_token_id
            )

            refresh_token_hash = hash_refresh_token(token=refresh_token)

            new_refresh_token = RefreshToken(
                id=refresh_token_id,
                session_id=session.id,
                user_id=user.id,
                family_token_id=family_id,
                token_hash=refresh_token_hash,
                expires_at=now + refresh_token_lifetime_in_days
            )

            await self._authUoW.refresh_tokens.add_and_flush(token=new_refresh_token)

            access_token = self._token_service.create_access_token(user_id=user.id, session_id=session.id)

            audit = {
                "actor_id": user.id, "audit_action":"USER_LOGIN",
                "resource_type":"User", "resource_id":user.id
            }

            await self._authUoW.audit_logs.add_and_flush(
                audit_schema=AuditLogCreate(**audit)
            )

            await self._authUoW.commit()

            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=int(self._token_service.access_token_lifetime * 60)
            )

        except IntegrityError as exc:
            await self._authUoW.rollback()

            raise DatabaseIntegrityError from exc

        except Exception:
            await self._authUoW.rollback()
            raise

    ## REFRESH TOKEN
    async def refresh_token_generation(self, refresh_token: str):
        payload = self._token_service.decode_refresh_token(token=refresh_token)

        try:

            user_id = UUID(payload.get("sub"))
            session_id = UUID(payload.get("sid"))
            family_id = UUID(payload.get("fid"))
            token_id = UUID(payload.get("jti"))

        except (KeyError, ValueError, TypeError):
            raise InvalidRefreshTokenError()

        now = datetime.now(tz=timezone.utc)

        try:
            refresh_token_record = await self._authUoW.refresh_tokens.get_for_update(token_id=token_id)
            if refresh_token_record is None:
                raise InvalidRefreshTokenError()

            candidate_hash = hash_refresh_token(token=refresh_token)

            if not hmac.compare_digest(candidate_hash, refresh_token_record.token_hash):
                raise InvalidRefreshTokenError()

            if refresh_token_record.user_id != user_id:
                raise InvalidRefreshTokenError()

            if refresh_token_record.session_id != session_id:
                raise InvalidRefreshTokenError()

            if refresh_token_record.token_family_id != family_id:
                raise InvalidRefreshTokenError()

            if refresh_token_record.expires_at <= now:
                raise InvalidRefreshTokenError()

            if refresh_token_record.revoked_at is not None:
                raise InvalidRefreshTokenError()

            if refresh_token_record.used_at is not None:
                await self._authUoW.refresh_tokens.revoke_token_family(family_token_id=family_id, revoked_at=now)
                await self._authUoW.security_event.add_and_flush(security_data=SecurityEvent(
                    user_id=user_id,
                    event_type="refresh_token_reuse_detected",
                    session_id=session_id,
                    family_token_id=family_id,
                    occurred_at=now
                ))
                await self._authUoW.commit()
                raise RefreshTokenReuseDetected()

            # use the current token
            refresh_token_record.used_at = now

            # If all checks pass, create new tokens
            new_token_id = uuid4()

            new_refresh_token = self._token_service.create_refresh_token(
                user_id=user_id, session_id=session_id, family_token_id=family_id, token_id=new_token_id
            )

            new_refresh_token_record = RefreshToken(
                id=new_token_id,
                user_id=user_id,
                session_id=session_id,
                family_token_id=family_id,
                token_hash=hash_refresh_token(token=new_refresh_token),
                expires_at=now + timedelta(days=self._token_service.refresh_token_lifetime)
            )

            self._authUoW.refresh_tokens.add_and_flush(token=new_refresh_token_record)

            new_access_token = self._token_service.create_access_token(user_id=user_id, session_id=session_id)

            await self._authUoW.commit()

            return TokenResponse(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                expires_in=int(self._token_service.access_token_lifetime * 60)
            )

        except IntegrityError as exc:
            await self._authUoW.rollback()

            raise DatabaseIntegrityError from exc

        except Exception:
            await self._authUoW.rollback()
            raise

    ## LOGOUT USER
    async def logout(self, user_id: UUID, session_id: UUID):

        now = datetime.now(tz=timezone.utc)

        try:
            session = await self._authUoW.auth_sessions.get_by_id_for_user(user_id=user_id, session_id=session_id)

            if session is None:
                return

            if session.revoked_at is not None:
                return

            await self._authUoW.refresh_tokens.revoke_token_family(family_id=session.family_token_id, revoked_at=now)

            await self._authUoW.auth_sessions.revoke_a_session(auth_session=session, reason="logout")

            await self._authUoW.audit_logs.add_and_flush(audit_schema=AuditLogCreate(
                actor_id=user_id, audit_action="LOGOUT", resource_type="AuthSession", resource_id=session_id
            ))

            await self._authUoW.commit()

        except IntegrityError as exc:
            await self._authUoW.rollback()

            raise DatabaseIntegrityError from exc

        except Exception:
            await self._authUoW.rollback()
            raise

    ## LOGOUT OF ALL SESSION/DEVICES
    async def logout_of_all_sessions(self, user_id: UUID):
        now = datetime.now(tz=timezone.utc)

        try:
            await self._authUoW.auth_sessions.revoke_all_session_for_user(
                user_id=user_id, revoked_at=now, revoked_reason="logout/revoke all sessions"
            )

            await self._authUoW.refresh_tokens.revoke_all_session_tokens_for_user(
                user_id=user_id, revoked_at=now
            )

            await self._authUoW.commit()

        except IntegrityError as exc:
            await self._authUoW.rollback()

            raise DatabaseIntegrityError from exc

        except Exception:
            await self._authUoW.rollback()
            raise

    ## GET ALL SESSION/DEVICES
    async def get_all_sessions(self, user_id: UUID):

        try:
            await self._authUoW.auth_sessions.get_all_sessions_by_user_id(user_id=user_id)
        except IntegrityError as exc:
            await self._authUoW.rollback()

            raise DatabaseIntegrityError from exc

        except Exception:
            await self._authUoW.rollback()
            raise

    ## DELETE A SESSION
    async def revoke_a_session(self, user_id: UUID, session_id: UUID):
        now = datetime.now(tz=timezone.utc)

        try:
            session = await self._authUoW.auth_sessions.get_by_id_for_user(user_id=user_id, session_id=session_id)
            if session is None:
                return

            if session.revoked_at is not None:
                return

            await self._authUoW.auth_sessions.revoke_a_session(auth_session=session, reason="user_revoked_session")

            await self._authUoW.refresh_tokens.revoke_token_family(family_id=session.family_token_id, revoked_at=now)

            await self._authUoW.audit_logs.add_and_flush(audit_schema=AuditLogCreate(
                actor_id=user_id, audit_action="SESSION_REVOKED", resource_type="AuthSession", resource_id=session_id
            ))

            await self._authUoW.commit()

        except IntegrityError as exc:
            await self._authUoW.rollback()

            raise DatabaseIntegrityError from exc

        except Exception:
            await self._authUoW.rollback()
            raise

    ## CREATE EMAIL VERIFICATION
    async def _create_verification(self, user: User):
        now = datetime.now(tz=timezone.utc)

        new_token = generate_url_safe_token()

        token_hash = hash_function(hashable=new_token)

        expires_at = now + timedelta(minutes=verification_settings.EMAIL_VERIFICATION_TOKEN_TTL_MINUTES)

        verification = EmailVerification(
            user_id=user.id,
            email=user.email,
            token_hash=token_hash,
            status=EmailVerificationStatus.PENDING,
            expires_at=expires_at
        )

        await self._authUoW.email.add_and_flush(verification=verification)

        await self._authUoW.outbox_messages.add_and_flush(
            event_type="email.verification",
            payload={
                "verification_id": str(verification.id),
                "user_id": str(user.id),
                "token": new_token
            }
        )


