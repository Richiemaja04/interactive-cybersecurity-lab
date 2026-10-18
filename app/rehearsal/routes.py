"""
app/rehearsal/routes.py — Rehearsal sessions and fault injection management.
"""

from __future__ import annotations

from datetime import datetime, timezone
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.audit.service import write_audit_event
from app.auth.decorators import require_tester
from app.extensions import db
from app.models.rehearsal import FaultInjection, FaultType, RehearsalSession

rehearsal_bp = Blueprint("rehearsal", __name__)


@rehearsal_bp.route("/")
@login_required
@require_tester
def index():
    """Rehearsal control room."""
    active_session = RehearsalSession.query.filter_by(
        user_id=current_user.id, is_active=True
    ).first()

    past_sessions = (
        RehearsalSession.query.filter_by(user_id=current_user.id, is_active=False)
        .order_by(RehearsalSession.id.desc())
        .limit(10)
        .all()
    )

    fault_types = [ft.value for ft in FaultType]

    return render_template(
        "rehearsal/index.html",
        active_session=active_session,
        past_sessions=past_sessions,
        fault_types=fault_types,
    )


@rehearsal_bp.route("/start", methods=["POST"])
@login_required
@require_tester
def start_session():
    """Start an isolated rehearsal session."""
    active = RehearsalSession.query.filter_by(
        user_id=current_user.id, is_active=True
    ).first()
    if active:
        flash("You already have an active rehearsal session.", "info")
        return redirect(url_for("rehearsal.index"))

    session = RehearsalSession(
        user_id=current_user.id,
        is_active=True,
    )
    db.session.add(session)
    db.session.commit()

    write_audit_event(
        action="REHEARSAL_SESSION_STARTED",
        user_id=current_user.id,
        detail={"session_id": session.id},
    )

    flash(f"Rehearsal session #{session.id} started. Results will be isolated from production history.", "success")
    return redirect(url_for("rehearsal.index"))


@rehearsal_bp.route("/end", methods=["POST"])
@login_required
@require_tester
def end_session():
    """End the active rehearsal session and clear all active faults."""
    active = RehearsalSession.query.filter_by(
        user_id=current_user.id, is_active=True
    ).first()
    if not active:
        flash("No active rehearsal session to end.", "info")
        return redirect(url_for("rehearsal.index"))

    active.is_active = False
    active.ended_at = datetime.now(timezone.utc)

    # Deactivate all associated faults
    for f in active.faults:
        f.is_enabled = False
        f.deactivated_at = datetime.now(timezone.utc)

    db.session.commit()

    write_audit_event(
        action="REHEARSAL_SESSION_ENDED",
        user_id=current_user.id,
        detail={"session_id": active.id},
    )

    flash("Rehearsal session ended. All injected faults have been cleared.", "info")
    return redirect(url_for("rehearsal.index"))


@rehearsal_bp.route("/toggle-fault", methods=["POST"])
@login_required
@require_tester
def toggle_fault():
    """Toggle a simulated fault on or off."""
    active = RehearsalSession.query.filter_by(
        user_id=current_user.id, is_active=True
    ).first()
    if not active:
        flash("You must start a rehearsal session before injecting faults.", "error")
        return redirect(url_for("rehearsal.index"))

    fault_name = request.form.get("fault_type")
    try:
        fault_enum = FaultType(fault_name)
    except ValueError:
        flash(f"Unknown fault type: {fault_name}", "error")
        return redirect(url_for("rehearsal.index"))

    existing_fault = next((f for f in active.faults if f.fault_type == fault_enum), None)
    if existing_fault:
        existing_fault.is_enabled = not existing_fault.is_enabled
        if existing_fault.is_enabled:
            existing_fault.activated_at = datetime.now(timezone.utc)
            existing_fault.deactivated_at = None
        else:
            existing_fault.deactivated_at = datetime.now(timezone.utc)
    else:
        existing_fault = FaultInjection(
            rehearsal_session_id=active.id,
            fault_type=fault_enum,
            is_enabled=True,
            activated_at=datetime.now(timezone.utc),
        )
        db.session.add(existing_fault)

    db.session.commit()

    write_audit_event(
        action="FAULT_INJECTION_TOGGLED",
        user_id=current_user.id,
        detail={
            "session_id": active.id,
            "fault_type": fault_enum.value,
            "is_enabled": existing_fault.is_enabled,
        },
    )

    state_str = "ENABLED [SIMULATED FAULT]" if existing_fault.is_enabled else "DISABLED"
    flash(f"Fault {fault_enum.value} is now {state_str}.", "info")
    return redirect(url_for("rehearsal.index"))
