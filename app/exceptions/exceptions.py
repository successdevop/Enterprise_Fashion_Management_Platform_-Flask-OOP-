class SeamlessFashionErrors(Exception):
    pass

class EmailAlreadyExistsError(SeamlessFashionErrors):
    pass

class UsernameAlreadyTakenError(SeamlessFashionErrors):
    pass

class PhoneNumberAlreadyExistsError(SeamlessFashionErrors):
    pass

class InvalidPasswordError(SeamlessFashionErrors):
    pass

class DatabaseIntegrityError(SeamlessFashionErrors):
    pass

class InvalidCredentialsError(SeamlessFashionErrors):
    pass

class EmailNotVerifiedError(SeamlessFashionErrors):
    pass

class InactiveAccountError(SeamlessFashionErrors):
    pass

class InvalidRefreshTokenError(SeamlessFashionErrors):
    pass

class RefreshTokenReuseDetected(SeamlessFashionErrors):
    pass

class InvalidAccessTokenError(SeamlessFashionErrors):
    pass

class InvalidAuthenticationCredentials(SeamlessFashionErrors):
    pass

class UserNotFoundError(SeamlessFashionErrors):
    pass