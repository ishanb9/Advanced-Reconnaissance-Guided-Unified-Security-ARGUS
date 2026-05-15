"""ARGUS · Enterprise authentication, authorization, and audit module.

Public API:

    from auth.integration import install_auth      # one-line FastAPI mount
    from auth.dependencies  import (                # FastAPI Depends
        get_current_user, require_role,
        require_permission, current_session,
    )
    from auth.audit         import audit_log       # emit audit entries
    from auth.rbac          import Role, Permission

See README.md for full architecture, role hierarchy, and integration
guide.  Nothing in this module modifies any existing ARGUS file.
"""

__version__ = "1.0.0"

# Re-export the most useful names so callers can `from auth import ...`
# without remembering submodule paths.
from auth.rbac import Role, Permission                       # noqa: E402
from auth.dependencies import (                              # noqa: E402
    get_current_user,
    require_role,
    require_permission,
    current_session,
)

__all__ = [
    "__version__",
    "Role",
    "Permission",
    "get_current_user",
    "require_role",
    "require_permission",
    "current_session",
]
