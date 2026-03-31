"""Enhanced security utilities for JWT, refresh tokens, MFA, and token blacklist."""
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp
import structlog
from jose import JWTError, jwt
from passlib.context import CryptContext

from netra.core.config import settings

logger = structlog.get_logger()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Password Hashing ──────────────────────────────────────────────────────────


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.

    Args:
        plain_password: The plain text password
        hashed_password: The hashed password to verify against

    Returns:
        True if the password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: The plain text password to hash

    Returns:
        The hashed password
    """
    return pwd_context.hash(password)


# ── JWT Access & Refresh Tokens ───────────────────────────────────────────────


def create_access_token(
    subject: str | uuid.UUID,
    expires_delta: timedelta | None = None,
    additional_claims: dict[str, Any] | None = None,
) -> str:
    """Create a JWT access token.

    Args:
        subject: The token subject (user ID or email)
        expires_delta: Optional custom expiration time
        additional_claims: Optional additional JWT claims

    Returns:
        The encoded JWT token
    """
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=settings.jwt_expire_minutes
        )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "iat": datetime.now(UTC),
        "type": "access",
    }

    if additional_claims:
        to_encode.update(additional_claims)

    return jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def create_refresh_token(
    subject: str | uuid.UUID,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT refresh token with longer expiration.

    Args:
        subject: The token subject (user ID)
        expires_delta: Optional custom expiration (default 7 days)

    Returns:
        The encoded JWT refresh token
    """
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(days=7)

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "iat": datetime.now(UTC),
        "type": "refresh",
        "jti": str(uuid.uuid4()),  # Unique ID for rotation tracking
    }

    return jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict | None:
    """Decode and validate a JWT access token.

    Args:
        token: The JWT token to decode

    Returns:
        The decoded token payload or None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        # Verify token type
        if payload.get("type") != "access":
            return None

        return payload
    except JWTError:
        return None


def decode_refresh_token(token: str) -> dict | None:
    """Decode and validate a JWT refresh token.

    Args:
        token: The JWT token to decode

    Returns:
        The decoded token payload or None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        # Verify token type
        if payload.get("type") != "refresh":
            return None

        return payload
    except JWTError:
        return None


# ── Token Blacklist ───────────────────────────────────────────────────────────


class TokenBlacklist:
    """In-memory token blacklist with Redis backend (fallback to dict).

    Stores revoked tokens until their expiration time.
    """

    def __init__(self) -> None:
        """Initialize the token blacklist."""
        self._blacklist: dict[str, datetime] = {}
        self._redis = None

    async def initialize_redis(self, redis_url: str) -> None:
        """Initialize Redis connection for distributed blacklist.

        Args:
            redis_url: Redis connection URL
        """
        try:
            import redis.asyncio as redis

            self._redis = redis.from_url(redis_url, decode_responses=True)
            logger.info("token_blacklist_redis_initialized")
        except Exception as e:
            logger.warning("token_blacklist_redis_failed", error=str(e))

    async def add(self, token: str, expires_at: datetime) -> bool:
        """Add a token to the blacklist.

        Args:
            token: The JWT token to blacklist
            expires_at: Token expiration time

        Returns:
            True if successful
        """
        if self._redis:
            try:
                ttl = int((expires_at - datetime.now(UTC)).total_seconds())
                if ttl > 0:
                    await self._redis.setex(f"blacklist:{token}", ttl, "1")
                    return True
            except Exception as e:
                logger.error("blacklist_redis_add_failed", error=str(e))

        # Fallback to in-memory
        self._blacklist[token] = expires_at
        return True

    async def is_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted.

        Args:
            token: The JWT token to check

        Returns:
            True if blacklisted, False otherwise
        """
        if self._redis:
            try:
                result = await self._redis.get(f"blacklist:{token}")
                return result is not None
            except Exception as e:
                logger.error("blacklist_redis_check_failed", error=str(e))

        # Fallback to in-memory
        self._cleanup_expired()
        return token in self._blacklist

    async def remove(self, token: str) -> bool:
        """Remove a token from the blacklist (cleanup).

        Args:
            token: The JWT token to remove

        Returns:
            True if successful
        """
        if self._redis:
            try:
                await self._redis.delete(f"blacklist:{token}")
                return True
            except Exception as e:
                logger.error("blacklist_redis_remove_failed", error=str(e))

        # Fallback to in-memory
        self._blacklist.pop(token, None)
        return True

    def _cleanup_expired(self) -> None:
        """Remove expired tokens from in-memory blacklist."""
        now = datetime.now(UTC)
        expired = [k for k, v in self._blacklist.items() if v < now]
        for k in expired:
            del self._blacklist[k]


# Global blacklist instance
token_blacklist = TokenBlacklist()


# ── MFA / TOTP ────────────────────────────────────────────────────────────────


def generate_mfa_secret() -> str:
    """Generate a new MFA secret key for TOTP.

    Returns:
        Base32-encoded secret key (16 characters)
    """
    return pyotp.random_base32()


def get_mfa_provisioning_uri(
    secret: str,
    email: str,
    issuer: str = "NETRA",
) -> str:
    """Generate MFA provisioning URI for QR code generation.

    Args:
        secret: The MFA secret key
        email: User's email address
        issuer: Service name (default "NETRA")

    Returns:
        otpauth:// URI for QR code generation
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_mfa_code(secret: str, code: str) -> bool:
    """Verify a TOTP MFA code.

    Args:
        secret: The MFA secret key
        code: The 6-digit code from authenticator app

    Returns:
        True if valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Allow 1 step tolerance


def generate_backup_codes(count: int = 10) -> list[str]:
    """Generate one-time backup codes for MFA recovery.

    Args:
        count: Number of codes to generate (default 10)

    Returns:
        List of backup codes
    """
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_urlsafe(6).upper()
        codes.append(code)
    return codes


def hash_backup_code(code: str) -> str:
    """Hash a backup code for storage.

    Args:
        code: Plain text backup code

    Returns:
        Hashed backup code
    """
    return get_password_hash(code)


def verify_backup_code(code: str, hashed_code: str) -> bool:
    """Verify a backup code against its hash.

    Args:
        code: Plain text backup code
        hashed_code: Hashed backup code

    Returns:
        True if valid, False otherwise
    """
    return verify_password(code, hashed_code)


# ── API Key Management ────────────────────────────────────────────────────────


def create_api_key() -> str:
    """Generate a new API key.

    Returns:
        A unique API key string (prefix: ntr_)
    """
    return f"ntr_{uuid.uuid4().hex}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage.

    Args:
        api_key: The plain text API key

    Returns:
        The hashed API key
    """
    return get_password_hash(api_key)


def verify_api_key(api_key: str, hashed_key: str) -> bool:
    """Verify an API key against its hash.

    Args:
        api_key: The plain text API key
        hashed_key: The hashed API key to verify against

    Returns:
        True if the API key matches, False otherwise
    """
    return verify_password(api_key, hashed_key)


# ── Password Reset Tokens ─────────────────────────────────────────────────────


def create_password_reset_token(
    user_id: str | uuid.UUID,
    expires_hours: int = 1,
) -> str:
    """Create a password reset token.

    Args:
        user_id: The user ID
        expires_hours: Token expiration in hours (default 1)

    Returns:
        The encoded JWT reset token
    """
    expire = datetime.now(UTC) + timedelta(hours=expires_hours)

    to_encode = {
        "exp": expire,
        "sub": str(user_id),
        "iat": datetime.now(UTC),
        "type": "password_reset",
        "jti": str(uuid.uuid4()),
    }

    return jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_password_reset_token(token: str) -> dict | None:
    """Decode and validate a password reset token.

    Args:
        token: The JWT token to decode

    Returns:
        The decoded token payload or None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        # Verify token type
        if payload.get("type") != "password_reset":
            return None

        return payload
    except JWTError:
        return None


# ── Session Management ────────────────────────────────────────────────────────


def generate_session_id() -> str:
    """Generate a unique session ID.

    Returns:
        Unique session identifier
    """
    return f"sess_{uuid.uuid4().hex}"


def get_session_fingerprint(user_agent: str, ip_address: str) -> str:
    """Generate a session fingerprint for device tracking.

    Args:
        user_agent: Browser user agent string
        ip_address: Client IP address

    Returns:
        Session fingerprint hash
    """
    import hashlib

    data = f"{user_agent}:{ip_address}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]
