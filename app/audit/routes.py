"""
app/audit/routes.py — Audit log viewing and inspection routes (Admin only).
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from app.auth.decorators import require_admin
from app.models.audit import AuditEvent

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/")
@login_required
@require_admin
def index():
    """List recent security audit events."""
    events = AuditEvent.query.order_by(AuditEvent.id.desc()).limit(100).all()
    return render_template("admin/audit.html", events=events)


@audit_bp.route("/<int:event_id>")
@login_required
@require_admin
def detail(event_id: int):
    """Retrieve details for a single audit event as JSON."""
    event = AuditEvent.query.get_or_404(event_id)
    return jsonify({
        "id": event.id,
        "action": event.action,
        "user_id": event.user_id,
        "username": event.user.username if event.user else None,
        "ip_address": event.ip_address,
        "timestamp": event.timestamp.isoformat(),
        "detail": event.detail,
    })
