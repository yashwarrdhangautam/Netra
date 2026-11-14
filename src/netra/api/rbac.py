"""Role checks for API routes (see docs/PRD.md section 5.3.2).

The implementations live in ``netra.api.routes.auth`` so that route modules can
import them without a circular import. This module re-exports them for app code.

- Any signed-in user may read (GET) data routes.
- Writes (POST, PUT, PATCH, DELETE) need the analyst or admin role.
- Viewer and client roles are read-only.
- Admin-only routes (user management, kill switch, settings) use ``require_admin``.
"""

from netra.api.routes.auth import WRITE_METHODS, WRITER_ROLES, require_access, require_admin

__all__ = ["WRITE_METHODS", "WRITER_ROLES", "require_access", "require_admin"]
