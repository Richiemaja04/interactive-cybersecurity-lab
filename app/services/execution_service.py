"""
app/services/execution_service.py — Execution lifecycle manager.

State machine: NotStarted → Queued → Running → Completed | Failed | Cancelled | Blocked

Key behaviors:
- Synchronous execution with configurable per-module timeout.
- Cooperative cancellation via DB flag polling.
- Partial evidence preserved on failure or cancellation.
- BLOCKED state triggered by scope violations — stops immediately.
- Stage-based progress via ExecutionEvent rows (no WebSockets).
- ExecutionState ≠ FindingVerificationStatus — never conflated.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from flask import current_app

from app.extensions import db
from app.models.execution import ExecutionEvent, ExecutionRun, ExecutionState

if TYPE_CHECKING:
    from app.tests._base import SecurityTestModule


class ExecutionTimeout(Exception):
    """Raised when a test module exceeds its allowed execution time."""


class ScopeViolation(Exception):
    """
    Raised when an external-target operation violates the approved scope.
    Triggers immediate BLOCKED state and audit event.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class ExecutionService:
    """Manages the lifecycle of a single ExecutionRun."""

    def __init__(self, run: ExecutionRun, module: "SecurityTestModule", timeout: int):
        self.run = run
        self.module = module
        self.timeout = timeout

    def execute(self, scenario, config: dict) -> ExecutionRun:
        """
        Run the module synchronously.
        Returns the updated ExecutionRun (state may be any terminal state).
        """
        self._transition(ExecutionState.RUNNING)

        app = current_app._get_current_object()
        result_holder: dict = {}
        error_holder: dict = {}

        def _run():
            with app.app_context():
                try:
                    result = self.module.execute(self.run, scenario, config)
                    result_holder["result"] = result
                except ScopeViolation as sv:
                    error_holder["scope_violation"] = sv
                except Exception as exc:
                    error_holder["exception"] = exc

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout)

        if thread.is_alive():
            # Timeout — thread continues briefly then is abandoned (daemon)
            self._handle_timeout()
            return self.run

        if "scope_violation" in error_holder:
            self._handle_scope_violation(error_holder["scope_violation"])
            return self.run

        if "exception" in error_holder:
            self._handle_exception(error_holder["exception"])
            return self.run

        result = result_holder.get("result")
        if result is None:
            self._transition(ExecutionState.FAILED, "Module produced no result")
            return self.run

        # Check cooperative cancellation outcome
        if result.state == ExecutionState.CANCELLED.value:
            self._transition(ExecutionState.CANCELLED, result.state_reason)
        elif result.state == ExecutionState.FAILED.value:
            self._transition(ExecutionState.FAILED, result.state_reason)
        else:
            self._transition(ExecutionState.COMPLETED)

        # Persist finding if produced
        if result.finding:
            db.session.add(result.finding)
            db.session.commit()

        return self.run

    # ── Private helpers ────────────────────────────────────────────────────────

    def _transition(self, state: ExecutionState, reason: str = "") -> None:
        """Update run state and timestamps atomically."""
        self.run.state = state
        self.run.state_reason = reason or None
        if state == ExecutionState.RUNNING:
            self.run.started_at = datetime.now(timezone.utc)
        elif state in (
            ExecutionState.COMPLETED,
            ExecutionState.FAILED,
            ExecutionState.CANCELLED,
            ExecutionState.BLOCKED,
        ):
            self.run.completed_at = datetime.now(timezone.utc)

        self._emit_event(state.value, reason)
        db.session.commit()

    def _emit_event(self, event_type: str, detail: str = "") -> None:
        event = ExecutionEvent(
            run_id=self.run.id,
            event_type=event_type,
            detail=detail[:512] if detail else None,
        )
        db.session.add(event)

    def _handle_timeout(self) -> None:
        current_app.logger.warning(
            "Execution timeout: run=%s module=%s timeout=%ds",
            self.run.id, self.module.slug, self.timeout,
        )
        self._transition(
            ExecutionState.FAILED,
            f"Execution exceeded {self.timeout}s timeout",
        )

    def _handle_scope_violation(self, sv: ScopeViolation) -> None:
        from app.audit.service import record_audit_event
        current_app.logger.warning(
            "Scope violation: run=%s reason=%s", self.run.id, sv.reason
        )
        record_audit_event(
            action="scope_violation",
            user=None,
            detail={"run_id": self.run.id, "reason": sv.reason},
        )
        self._transition(ExecutionState.BLOCKED, sv.reason)

    def _handle_exception(self, exc: Exception) -> None:
        # Log internally — never expose exception details to users
        current_app.logger.error(
            "Execution exception: run=%s module=%s error=%s",
            self.run.id, self.module.slug, type(exc).__name__,
            exc_info=True,
        )
        self._transition(ExecutionState.FAILED, "An internal error occurred during execution")
