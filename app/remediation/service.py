"""
app/remediation/service.py — Remediation action workflow with optimistic locking.

Enforces:
- Explicit POST confirmation
- Optimistic version locking (rejects stale actions with StaleActionError)
- Atomic before/after state capture in RemediationAction
- Immutable RemediationAudit logging
- Reversal workflow for built-in lab remediations
"""

from __future__ import annotations

from app.extensions import db
from app.models.finding import Finding
from app.models.remediation import OutcomeEnum, RemediationAction, RemediationAudit
from app.models.scenario import Scenario, ScenarioState, ScenarioVersion


class StaleActionError(Exception):
    """Raised when an action is attempted against an out-of-date scenario version."""


class RemediationService:
    @classmethod
    def apply_fix(
        cls,
        finding_id: int,
        user_id: int,
        fix_name: str,
        expected_scenario_version: int,
        description: str | None = None,
    ) -> RemediationAction:
        """
        Applies a remediation fix atomically with optimistic version lock validation.
        """
        finding = Finding.query.get_or_404(finding_id)
        run = finding.run
        scenario = Scenario.query.filter_by(test_id=run.test_id).first()
        if not scenario:
            raise ValueError("Associated scenario not found.")

        # Optimistic locking: verify version has not drifted
        if scenario.current_version != expected_scenario_version:
            raise StaleActionError(
                f"Scenario state has changed (current v{scenario.current_version} != expected v{expected_scenario_version}). "
                "Please reload the latest state before applying remediation."
            )

        before_state = {
            "state": scenario.state.value,
            "version": scenario.current_version,
            "config": scenario.config_json,
        }

        # Apply fix: switch scenario to SECURE
        scenario.state = ScenarioState.SECURE
        scenario.current_version += 1

        after_state = {
            "state": scenario.state.value,
            "version": scenario.current_version,
            "config": scenario.config_json,
        }

        # Create linear ScenarioVersion snapshot
        sv = ScenarioVersion(
            scenario_id=scenario.id,
            version=scenario.current_version,
            snapshot_json=after_state,
            change_description=f"Remediation fix '{fix_name}' applied",
            changed_by_id=user_id,
        )
        db.session.add(sv)

        action = RemediationAction(
            finding_id=finding.id,
            user_id=user_id,
            fix_name=fix_name,
            description=description or f"Applied automated remediation fix: {fix_name}",
            scenario_version_at_action=expected_scenario_version,
            before_state=before_state,
            after_state=after_state,
            outcome=OutcomeEnum.RESOLVED,
            verification_notes="Remediation applied. Live scenario switched to SECURE.",
            is_reversal=False,
        )
        db.session.add(action)
        db.session.flush()

        audit = RemediationAudit(
            action_id=action.id,
            user_id=user_id,
            event_type="applied",
            detail=f"Remediation '{fix_name}' applied to finding #{finding.id}. Version stepped to v{scenario.current_version}.",
        )
        db.session.add(audit)
        db.session.commit()

        return action

    @classmethod
    def reverse_fix(
        cls,
        action_id: int,
        user_id: int,
        expected_scenario_version: int,
    ) -> RemediationAction:
        """
        Reverses a previously applied remediation action.
        """
        orig_action = RemediationAction.query.get_or_404(action_id)
        finding = orig_action.finding
        run = finding.run
        scenario = Scenario.query.filter_by(test_id=run.test_id).first()
        if not scenario:
            raise ValueError("Associated scenario not found.")

        if scenario.current_version != expected_scenario_version:
            raise StaleActionError(
                f"Scenario state has changed (current v{scenario.current_version} != expected v{expected_scenario_version}). "
                "Please reload the latest state before reversing."
            )

        before_state = {
            "state": scenario.state.value,
            "version": scenario.current_version,
        }

        # Revert scenario to VULNERABLE
        scenario.state = ScenarioState.VULNERABLE
        scenario.current_version += 1

        after_state = {
            "state": scenario.state.value,
            "version": scenario.current_version,
        }

        sv = ScenarioVersion(
            scenario_id=scenario.id,
            version=scenario.current_version,
            snapshot_json=after_state,
            change_description=f"Reversed remediation fix '{orig_action.fix_name}'",
            changed_by_id=user_id,
        )
        db.session.add(sv)

        reversal_action = RemediationAction(
            finding_id=finding.id,
            user_id=user_id,
            fix_name=f"reverse_{orig_action.fix_name}",
            description=f"Reversed fix #{orig_action.id} ({orig_action.fix_name})",
            scenario_version_at_action=expected_scenario_version,
            before_state=before_state,
            after_state=after_state,
            outcome=OutcomeEnum.PERSISTS,
            verification_notes="Reversal applied. Live scenario restored to VULNERABLE.",
            is_reversal=True,
            reversed_action_id=orig_action.id,
        )
        db.session.add(reversal_action)
        db.session.flush()

        audit = RemediationAudit(
            action_id=reversal_action.id,
            user_id=user_id,
            event_type="reversed",
            detail=f"Reversed remediation #{orig_action.id}. Restored finding #{finding.id} to vulnerable state.",
        )
        db.session.add(audit)
        db.session.commit()

        return reversal_action
