"""
app/presentation_sequences/routes.py — Guided presentation sequence routes and step runner.
"""

from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.auth.decorators import require_tester
from app.extensions import db
from app.models.execution import ExecutionRun, ExecutionState
from app.models.preset import PresentationSequence, SequenceStep
from app.models.scenario import Scenario, ScenarioState, TestDefinition
from app.services.execution_service import ExecutionService
from app.tests.controller import ensure_test_scenario
from app.tests.registry import get_all_modules, get_module_by_slug
from scripts.seed_test_definitions import TEST_DEFINITIONS

sequences_bp = Blueprint("sequences", __name__)


def ensure_default_sequence() -> PresentationSequence:
    """Ensures the default 10-test presentation sequence is present in the database."""
    default_seq = PresentationSequence.query.filter_by(is_default=True).first()
    if default_seq:
        return default_seq

    # Ensure all test definitions are present
    for td_data in TEST_DEFINITIONS:
        ensure_test_scenario(td_data["slug"])

    seq = PresentationSequence(
        name="Standard 10-Check Browser Security Walkthrough",
        description="Comprehensive presentation sequence covering all 10 browser-based security checks in instructional order.",
        version=1,
        is_default=True,
        is_active=True,
    )
    db.session.add(seq)
    db.session.flush()

    for idx, td_data in enumerate(TEST_DEFINITIONS, start=1):
        test_def = TestDefinition.query.filter_by(slug=td_data["slug"]).first()
        step = SequenceStep(
            sequence_id=seq.id,
            step_order=idx,
            test_id=test_def.id,
        )
        db.session.add(step)

    db.session.commit()
    return seq


@sequences_bp.route("/")
@login_required
@require_tester
def index():
    """List presentation sequences."""
    ensure_default_sequence()
    sequences = PresentationSequence.query.filter_by(is_active=True).all()
    return render_template("sequences/index.html", sequences=sequences)


@sequences_bp.route("/<int:sequence_id>")
@login_required
@require_tester
def present(sequence_id: int):
    """Guided presentation runner."""
    sequence = PresentationSequence.query.get_or_404(sequence_id)
    step_num = request.args.get("step", 1, type=int)

    total_steps = len(sequence.steps)
    if total_steps == 0:
        flash("This sequence contains no steps.", "warning")
        return redirect(url_for("sequences.index"))

    step_num = max(1, min(step_num, total_steps))
    current_step = next((s for s in sequence.steps if s.step_order == step_num), sequence.steps[0])

    test_def = current_step.test_definition
    _, scenario = ensure_test_scenario(test_def.slug)
    module = get_module_by_slug(test_def.slug)

    presenter_notes = module.get_presenter_notes() if module else None
    verification_steps = module.get_verification_steps(None) if module else []
    remediation = module.get_remediation(None) if module else None

    # Latest run for this test by current user
    latest_run = (
        ExecutionRun.query.filter_by(test_id=test_def.id, user_id=current_user.id)
        .order_by(ExecutionRun.id.desc())
        .first()
    )

    return render_template(
        "sequences/present.html",
        sequence=sequence,
        current_step=current_step,
        step_num=step_num,
        total_steps=total_steps,
        test_def=test_def,
        scenario=scenario,
        presenter_notes=presenter_notes,
        verification_steps=verification_steps,
        remediation=remediation,
        latest_run=latest_run,
    )


@sequences_bp.route("/<int:sequence_id>/step/<int:step_order>/execute", methods=["POST"])
@login_required
@require_tester
def execute_step(sequence_id: int, step_order: int):
    """Execute the security check for a specific presentation step."""
    sequence = PresentationSequence.query.get_or_404(sequence_id)
    step = next((s for s in sequence.steps if s.step_order == step_order), None)
    if not step:
        abort(404, "Step not found")

    test_def, scenario = ensure_test_scenario(step.test_definition.slug)
    module = get_module_by_slug(test_def.slug)

    run = ExecutionRun(
        test_id=test_def.id,
        user_id=current_user.id,
        scenario_id=scenario.id,
        state=ExecutionState.QUEUED,
        scenario_version_at_run=scenario.current_version,
        is_rehearsal=False,
    )
    db.session.add(run)
    db.session.commit()

    service = ExecutionService(run=run, module=module, timeout=10)
    service.execute(scenario=scenario, config={})

    flash(f"Test executed for Step {step_order}: {test_def.name}.", "success")
    return redirect(url_for("sequences.present", sequence_id=sequence.id, step=step_order))
