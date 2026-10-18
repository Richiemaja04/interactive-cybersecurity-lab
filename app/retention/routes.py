"""
app/retention/routes.py — Retention management and manual purge trigger routes (Admin only).
"""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from app.auth.decorators import require_admin
from app.models.retention import RetentionJob
from app.retention.service import RetentionService

retention_bp = Blueprint("retention", __name__)


@retention_bp.route("/")
@login_required
@require_admin
def index():
    """List historical retention cleanup jobs."""
    jobs = RetentionJob.query.order_by(RetentionJob.id.desc()).limit(25).all()
    return render_template("admin/retention.html", jobs=jobs)


@retention_bp.route("/run", methods=["POST"])
@login_required
@require_admin
def run_job():
    """Trigger data retention cleanup job."""
    try:
        job = RetentionService.execute_retention_job(triggered_by_id=current_user.id)
        flash(f"Retention purge completed: {job.records_deleted} records cleaned.", "success")
    except Exception as e:
        flash(f"Retention job failed: {e}", "error")

    return redirect(url_for("retention.index"))
