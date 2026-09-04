import hashlib
import hmac
import secrets

from app.config.config import verification_settings


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def generate_url_safe_token() -> str:
    return secrets.token_urlsafe(48)


def hash_function(hashable: str) -> str:
    return hmac.new(
        key=verification_settings.VERIFICATION_TOKEN_PEPPER.encode(),
        msg=hashable.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()


def verify_hash(hashable: str, expected_hash: str) -> bool:
    token_hash = hash_function(hashable=hashable)

    return hmac.compare_digest(token_hash, expected_hash)

