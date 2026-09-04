from pathlib import Path

from pydantic import SecretStr, AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


BASE_DIR = Path(__file__).resolve().parents[2]

_base_config = SettingsConfigDict(
    env_file=BASE_DIR / ".env",
    env_ignore_empty=True,
    env_file_encoding="utf-8",
    extra='ignore',
    case_sensitive=True
)


class ApplicationSettings(BaseSettings):
    APP_NAME: str
    APP_DOMAIN: AnyHttpUrl
    FRONTEND_URL: str

    model_config = _base_config


class DatabaseSettings(BaseSettings):
    POSTGRES_SERVER: str
    POSTGRES_PORT: int
    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr
    POSTGRES_DB: str

    DB_ECHO: bool

    model_config = _base_config

    @property
    def postgres_url(self) -> URL:
        return URL.create(
            drivername="postgresql+asyncpg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD.get_secret_value(),
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB
        )


class RedisSettings(BaseSettings):
    REDIS_HOST: str
    REDIS_PORT: str

    model_config = _base_config

    @property
    def redis_url(self):
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{0}"

    @property
    def celery_broker_url(self):
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{1}"

    @property
    def celery_result_backend(self):
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{2}"


class SecuritySetting(BaseSettings):
    JWT_PRIVATE_KEY: SecretStr
    JWT_PUBLIC_KEY: SecretStr
    JWT_ALGORITHM: str
    JWT_ISSUER: str
    JWT_AUDIENCE: str
    JWT_CURRENT_KID: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int

    model_config = _base_config


class EmailSettings(BaseSettings):
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_FROM_NAME: str
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    USE_CREDENTIALS: bool = True
    VALIDATE_CERTS: bool = False

    model_config = _base_config


class VerificationSettings(BaseSettings):
    VERIFICATION_TOKEN_PEPPER: str
    EMAIL_VERIFICATION_TOKEN_TTL_MINUTES: int
    EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS: int
    EMAIL_VERIFICATION_MAX_SENDS_PER_DAY: int


# APPLICATION SETTINGS
app_settings = ApplicationSettings() # type: ignore[call-arg] #loaded from .env file

# DATABASE SETTINGS
db_settings = DatabaseSettings()  # type: ignore[call-arg] #loaded from .env file

# REDIS SETTINGS
redis_settings = RedisSettings() # type: ignore[call-arg] #loaded from .env file

# JWT SECURITY KEY
security = SecuritySetting()  # type: ignore[call-arg] #loaded from .env file
PRIVATE_KEY = security.JWT_PRIVATE_KEY.get_secret_value().replace("\\n", "\n")
PUBLIC_KEY = security.JWT_PUBLIC_KEY.get_secret_value().replace("\\n", "\n")

# EMAIL SETTINGS
email_settings = EmailSettings() # type: ignore[call-arg] #loaded from .env file

# VERIFICATION SETTINGS
verification_settings = VerificationSettings() # type: ignore[call-arg] #loaded from .env file