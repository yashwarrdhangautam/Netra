"""Shared column types.

``JSONB`` is ``jsonb`` on PostgreSQL, the engine the app runs on, and plain ``JSON``
elsewhere (SQLite in tests). Models used to alias the generic JSON type, so the live schema
drifted: some columns were ``json`` and others ``jsonb``. Migration 022 aligns them.
"""

from sqlalchemy import JSON
from sqlalchemy.dialects import postgresql

JSONB = JSON().with_variant(postgresql.JSONB(), "postgresql")
