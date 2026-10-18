"""app/auth/decorators.py — Server-side role enforcement decorators."""

from __future__ import annotations

from functools import wraps

from flask import abort, current_app
from flask_login import current_user

from app.models.user import RoleEnum


def require_role(minimum_role: RoleEnum):
    """
    Decorator that enforces a minimum role on the server.
    The client-supplied role is NEVER trusted — only the DB record is used.
    Returns 403 on authorization failure without leaking internal details.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.has_role(minimum_role):
                current_app.logger.warning(
                    "Authorization failure: user=%s role=%s required=%s path=%s",
                    current_user.id,
                    current_user.role.value,
                    minimum_role.value,
                    # Path is logged internally only — never returned to client
                    "internal",
                )
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_tester(f):
    """Shorthand: require Tester or Administrator role."""
    return require_role(RoleEnum.TESTER)(f)


def require_admin(f):
    """Shorthand: require Administrator role."""
    return require_role(RoleEnum.ADMINISTRATOR)(f)


def owns_resource(resource_user_id_getter):
    """
    Decorator that ensures the authenticated user owns the requested resource.
    Used to prevent cross-tester data access.

    Usage:
        @owns_resource(lambda: int(request.view_args["user_id"]))
        def my_route(user_id): ...
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            resource_owner_id = resource_user_id_getter()
            if not current_user.is_administrator and current_user.id != resource_owner_id:
                current_app.logger.warning(
                    "Ownership check failed: requester=%s resource_owner=%s",
                    current_user.id,
                    resource_owner_id,
                )
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator
