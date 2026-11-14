"""Create the first NETRA administrator account.

Run once after installation:

    python -m netra.cli.create_admin

The password is read with a hidden prompt and is never printed or stored in
plain text. The account is created active and verified, with the admin role.
"""

from __future__ import annotations

import asyncio
import getpass
import re
import sys

from sqlalchemy import select

from netra.core.passwords import MIN_PASSWORD_LENGTH, validate_password
from netra.core.security import get_password_hash
from netra.db.models.user import User, UserRole
from netra.db.session import async_session_factory

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

__all__ = ["MIN_PASSWORD_LENGTH", "validate_password", "create_admin", "main"]


async def create_admin(email: str, full_name: str | None, password: str) -> None:
    """Insert the admin user, refusing duplicates."""
    async with async_session_factory() as session:
        existing = await session.execute(select(User.id).where(User.email == email))
        if existing.first() is not None:
            raise ValueError(f"a user with email {email} already exists")
        session.add(
            User(
                email=email,
                full_name=full_name or None,
                hashed_password=get_password_hash(password),
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True,
            )
        )
        await session.commit()


def main() -> int:
    """Interactive entry point. Returns a process exit code."""
    email = input("Admin email: ").strip().lower()
    if not _EMAIL_RE.match(email):
        print("Invalid email address.", file=sys.stderr)
        return 2
    full_name = input("Full name (optional): ").strip()
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Repeat password: ")
    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    problem = validate_password(password)
    if problem:
        print(f"Rejected: {problem}.", file=sys.stderr)
        return 2
    try:
        asyncio.run(create_admin(email, full_name, password))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Admin account created for {email}. You can now sign in.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
