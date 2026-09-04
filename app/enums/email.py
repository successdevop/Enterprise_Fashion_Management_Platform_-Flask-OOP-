from enum import Enum


class EmailVerificationStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    VERIFIED = "verified"
    EXPIRED = "expired"
    FAILED = "failed"
    SUPERSEDED = "superseded"
