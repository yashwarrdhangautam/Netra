"""Database module for NETRA."""
from netra.db.engine import get_engine
from netra.db.session import get_db

__all__ = [
    "get_engine",
    "get_db",
]
