"""
app/remediation/routes.py — Routes for remediation action execution and audit review.
"""

from __future__ import annotations

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.auth.decorators import require_tester
from app.models.finding import Finding
from app.models.remediation import RemediationAction
from app.models.scenario import Scenario
from app.remediation.service import RemediationService, StaleActionError

remediation_bp = Blueprint("remediation", __name__)


@remediation_bp.route("/")
@login_required
@require_tester
def index():
    """List recent remediation actions."""
    actions = (
        RemediationAction.query.filter_by(user_id=current_user.id)
        .order_by(RemediationAction.id.desc())
        .limit(25)
        .all()
    )
    return render_template("remediation/index.html", actions=actions)


@remediation_bp.route("/apply", methods=["POST"])
@login_required
@require_tester
def apply_fix():
    """Apply remediation with optimistic version check."""
    finding_id = request.form.get("finding_id", type=int)
    fix_name = request.form.get("fix_name", "").strip()
    expected_version = request.form.get("expected_version", type=int)
    redirect_url = request.form.get("redirect_url")

    if not finding_id or not fix_name or expected_version is None:
        flash("Invalid remediation request parameters.", "error")
        return redirect(redirect_url or url_for("remediation.index"))

    try:
        action = RemediationService.apply_fix(
            finding_id=finding_id,
            user_id=current_user.id,
            fix_name=fix_name,
            expected_scenario_version=expected_version,
        )
        flash(f"Remediation '{fix_name}' applied successfully. Finding marked as resolved.", "success")
    except StaleActionError as sae:
        flash(f"Remediation conflict: {sae}", "error")
    except Exception as e:
        flash(f"Failed to apply remediation: {e}", "error")

    return redirect(redirect_url or url_for("remediation.index"))


@remediation_bp.route("/<int:action_id>/reverse", methods=["POST"])
@login_required
@require_tester
def reverse_fix(action_id: int):
    """Reverse a previously applied remediation."""
    expected_version = request.form.get("expected_version", type=int)
    redirect_url = request.form.get("redirect_url")

    if expected_version is None:
        flash("Expected scenario version is required for safe reversal.", "error")
        return redirect(redirect_url or url_for("remediation.index"))

    try:
        reversal = RemediationService.reverse_fix(
            action_id=action_id,
            user_id=current_user.id,
            expected_scenario_version=expected_version,
        )
        flash("Remediation successfully reversed. Scenario restored to vulnerable state.", "info")
    except StaleActionError as sae:
        flash(f"Reversal conflict: {sae}", "error")
    except Exception as e:
        flash(f"Failed to reverse remediation: {e}", "error")

    return redirect(redirect_url or url_for("remediation.index"))
