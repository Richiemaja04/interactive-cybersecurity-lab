"""
app/external_targets/routes.py — External target approval administration.
"""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.auth.decorators import require_admin
from app.extensions import db
from app.models.external import ExternalTargetApproval

external_bp = Blueprint("external_targets", __name__)


@external_bp.route("/")
@login_required
@require_admin
def index():
    """List approved external hostnames."""
    approvals = ExternalTargetApproval.query.order_by(ExternalTargetApproval.hostname).all()
    return render_template("admin/external_targets.html", approvals=approvals)


@external_bp.route("/new", methods=["POST"])
@login_required
@require_admin
def approve_target():
    """Approve a new external target hostname."""
    hostname = request.form.get("hostname", "").strip().lower()
    notes = request.form.get("approval_notes", "").strip()

    if not hostname:
        flash("Hostname cannot be empty.", "error")
        return redirect(url_for("external_targets.index"))

    existing = ExternalTargetApproval.query.filter_by(hostname=hostname).first()
    if existing:
        existing.is_active = True
        existing.approval_notes = notes
        db.session.commit()
        flash(f"Re-activated approval for hostname '{hostname}'.", "success")
        return redirect(url_for("external_targets.index"))

    approval = ExternalTargetApproval(
        hostname=hostname,
        approved_by_id=current_user.id,
        approval_notes=notes,
        is_active=True,
    )
    db.session.add(approval)
    db.session.commit()

    flash(f"Hostname '{hostname}' successfully approved for external testing.", "success")
    return redirect(url_for("external_targets.index"))


@external_bp.route("/<int:target_id>/deactivate", methods=["POST"])
@login_required
@require_admin
def deactivate_target(target_id: int):
    """Revoke approval for an external target."""
    approval = ExternalTargetApproval.query.get_or_404(target_id)
    approval.is_active = False
    db.session.commit()

    flash(f"Target '{approval.hostname}' has been deactivated.", "info")
    return redirect(url_for("external_targets.index"))
