"""Password policy shared by the CLI and the API."""

MIN_PASSWORD_LENGTH = 12


def validate_password(password: str) -> str | None:
    """Return why a password is rejected, or None if it is acceptable."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    if password.lower() == password or password.upper() == password:
        return "password must mix upper- and lower-case letters"
    if not any(ch.isdigit() for ch in password):
        return "password must contain a digit"
    return None
