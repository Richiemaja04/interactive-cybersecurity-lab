"""
app/tests/_base.py — Shared SecurityTestModule protocol and data classes.

All ten test modules must implement this interface.
This enforces consistent output structures, evidence provenance,
and finding classification across every module.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.evidence import EvidenceRecord
    from app.models.execution import ExecutionRun
    from app.models.finding import Finding
    from app.models.scenario import Scenario


# ── Data classes returned by each module ──────────────────────────────────────

@dataclasses.dataclass
class PreconditionResult:
    """Result of pre-execution validation."""
    ok: bool
    reason: str = ""


@dataclasses.dataclass
class ExecutionResult:
    """
    Outcome of a single module execution.
    state is ExecutionState value; finding may be None (completed without finding).
    """
    state: str                           # ExecutionState enum value
    summary: str
    evidence: list                        # list[EvidenceRecord]
    finding: "Finding | None" = None
    state_reason: str = ""               # For FAILED / CANCELLED / BLOCKED


@dataclasses.dataclass
class RemediationGuidance:
    """Remediation information returned by a module."""
    summary: str
    steps: list[str]
    references: list[str]
    has_one_click_fix: bool = False
    fix_name: str | None = None          # Machine-readable fix identifier


@dataclasses.dataclass
class PresenterNotes:
    """Structured presenter notes for guided presentation mode."""
    objective: str
    demonstration_steps: list[str]
    evidence_meaning: str
    talking_points: list[str]
    remediation_takeaway: str


@dataclasses.dataclass
class SimulatedResult:
    """
    Replay/fallback result when live behavior cannot safely be demonstrated.
    MUST be labeled as simulated — never presented as live evidence.
    """
    summary: str
    simulated_evidence: list             # list[EvidenceRecord] with SIMULATED provenance
    label: str = "[SIMULATED]"           # Visible label — must appear in UI


# ── Abstract base class ────────────────────────────────────────────────────────

class SecurityTestModule(ABC):
    """
    Abstract base class for all ten security test modules.

    Contract guarantees:
    - Every module produces structured, consistent output.
    - Evidence provenance is set accurately (drives finding classification).
    - Simulated results are clearly labeled and never classified as Confirmed.
    - Sanitize_evidence is called before any evidence reaches the database.
    """

    # ── Module metadata (set as class attributes in subclasses) ───────────────
    test_id: str        # "01" – "10"
    name: str           # Original presentation name
    slug: str           # URL-safe identifier
    category: str       # e.g. "Information disclosure"

    @abstractmethod
    def validate_preconditions(self, scenario: "Scenario") -> PreconditionResult:
        """
        Check that the scenario and environment are ready for execution.
        Called before execute(). Return ok=False with a reason to block the run.
        """
        ...

    @abstractmethod
    def execute(
        self,
        run: "ExecutionRun",
        scenario: "Scenario",
        config: dict,
    ) -> ExecutionResult:
        """
        Run the test.
        Must poll run.cancel_requested periodically for cooperative cancellation.
        Must respect the configured execution timeout.
        Must preserve partial evidence on failure or cancellation.
        """
        ...

    @abstractmethod
    def collect_evidence(self, run: "ExecutionRun") -> list:
        """Gather and return raw evidence records for this run."""
        ...

    @abstractmethod
    def sanitize_evidence(self, evidence: list) -> list:
        """
        Strip credentials, stack traces, internal paths, and unnecessary payloads.
        Called before evidence is stored in the database or shown to users.
        """
        ...

    @abstractmethod
    def classify_finding(self, evidence: list) -> "Finding | None":
        """
        Classify collected evidence into a Finding.
        Returns None if no finding (completed run with no issue observed).

        Classification rules:
        - Simulated evidence → VerificationStatus.SIMULATED
        - Mixed live + simulated (live not definitive) → INCONCLUSIVE
        - Live + confirmed authorization failure → CONFIRMED
        - Live but ambiguous → POTENTIAL
        """
        ...

    @abstractmethod
    def get_remediation(self, finding: "Finding") -> RemediationGuidance:
        """Return remediation guidance for a finding."""
        ...

    @abstractmethod
    def get_verification_steps(self, finding: "Finding") -> list[str]:
        """Return ordered steps to verify that a remediation was effective."""
        ...

    @abstractmethod
    def get_presenter_notes(self) -> PresenterNotes:
        """Return structured presenter notes for guided presentation mode."""
        ...

    def simulate(self, scenario: "Scenario") -> SimulatedResult:
        """
        Return a pre-scripted simulation when live behavior is unavailable/unsafe.
        Override in modules where simulation is the designated fallback.
        Default implementation raises NotImplementedError.
        """
        raise NotImplementedError(
            f"Module {self.slug} does not implement a simulation fallback. "
            "Use a controlled scenario instead."
        )

    def __repr__(self) -> str:
        return f"<SecurityTestModule {self.test_id}: {self.name}>"
