"""
app/admin/routes.py — Admin control panel routes.
"""

from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

from app.auth.decorators import require_admin
from app.models.audit import AuditEvent
from app.models.execution import ExecutionRun
from app.models.preset import Preset
from app.models.user import User

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/")
@login_required
@require_admin
def index():
    """Admin dashboard overview."""
    user_count = User.query.count()
    run_count = ExecutionRun.query.count()
    preset_count = Preset.query.filter_by(is_active=True).count()
    audit_count = AuditEvent.query.count()
    users = User.query.order_by(User.id).all()

    return render_template(
        "admin/index.html",
        user_count=user_count,
        run_count=run_count,
        preset_count=preset_count,
        audit_count=audit_count,
        users=users,
    )
