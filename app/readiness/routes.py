"""
app/readiness/routes.py — Routes for pre-sequence readiness checks.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from app.auth.decorators import require_tester
from app.readiness.service import ReadinessService

readiness_bp = Blueprint("readiness", __name__)


@readiness_bp.route("/")
@login_required
@require_tester
def index():
    report = ReadinessService.run_all_checks()
    return render_template("readiness/index.html", report=report)


@readiness_bp.route("/check")
def check_api():
    report = ReadinessService.run_all_checks()
    return jsonify({
        "overall_status": report.overall_status,
        "can_proceed": report.can_proceed,
        "checks": [
            {
                "name": c.name,
                "status": c.status,
                "detail": c.detail,
                "essential": c.essential,
            }
            for c in report.checks
        ],
    })
