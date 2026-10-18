"""
tests/unit/test_finding_classifier.py — Phase 2: Finding classification engine unit tests.
"""

from __future__ import annotations

import pytest

from app.findings.classifier import classify, summarize
from app.models.evidence import EvidenceRecord, EvidenceType, ProvenanceEnum
from app.models.finding import (
    ConfidenceEnum,
    Finding,
    SeverityEnum,
    VerificationStatus,
)


def _make_evidence(provenance: ProvenanceEnum, is_simulated: bool = False) -> EvidenceRecord:
    """Helper to instantiate an in-memory EvidenceRecord."""
    return EvidenceRecord(
        run_id=1,
        provenance=provenance,
        evidence_type=EvidenceType.HTTP_RESPONSE,
        title="Sample Evidence",
        sanitized_detail={"status": 200},
        observation="Sample observation",
        is_simulated=is_simulated,
    )


class TestFindingClassificationRules:
    """Tests the 4 verification status paths and classification invariants."""

    def test_simulated_only_produces_simulated_status(self):
        evidence = [_make_evidence(ProvenanceEnum.SIMULATED, is_simulated=True)]
        finding = classify(
            evidence_records=evidence,
            title="Simulated Finding",
            description="Testing simulated classification",
            severity=SeverityEnum.HIGH,
            run_id=1,
        )
        assert finding is not None
        assert finding.verification_status == VerificationStatus.SIMULATED
        assert finding.confidence == ConfidenceEnum.UNKNOWN

    def test_mixed_live_and_simulated_produces_inconclusive(self):
        evidence = [
            _make_evidence(ProvenanceEnum.OBSERVED_LIVE),
            _make_evidence(ProvenanceEnum.SIMULATED, is_simulated=True),
        ]
        finding = classify(
            evidence_records=evidence,
            title="Mixed Evidence Finding",
            description="Testing mixed classification",
            severity=SeverityEnum.MEDIUM,
            run_id=1,
            authorization_failure_confirmed=False,
        )
        assert finding is not None
        assert finding.verification_status == VerificationStatus.INCONCLUSIVE
        assert finding.confidence == ConfidenceEnum.LOW

    def test_live_confirmed_auth_failure_produces_confirmed(self):
        evidence = [_make_evidence(ProvenanceEnum.OBSERVED_LIVE)]
        finding = classify(
            evidence_records=evidence,
            title="Confirmed Vulnerability",
            description="Live unauthorized access confirmed",
            severity=SeverityEnum.CRITICAL,
            run_id=1,
            authorization_failure_confirmed=True,
        )
        assert finding is not None
        assert finding.verification_status == VerificationStatus.CONFIRMED
        assert finding.confidence == ConfidenceEnum.HIGH

    def test_controlled_scenario_produces_potential(self):
        evidence = [_make_evidence(ProvenanceEnum.CONTROLLED_SCENARIO)]
        finding = classify(
            evidence_records=evidence,
            title="Controlled Lab Finding",
            description="Controlled lab reproduction",
            severity=SeverityEnum.HIGH,
            run_id=1,
        )
        assert finding is not None
        assert finding.verification_status == VerificationStatus.POTENTIAL
        assert finding.confidence == ConfidenceEnum.MEDIUM

    def test_empty_evidence_returns_none(self):
        finding = classify(
            evidence_records=[],
            title="No Evidence Finding",
            description="Empty list",
            severity=SeverityEnum.LOW,
            run_id=1,
        )
        assert finding is None

    def test_simulated_evidence_never_produces_confirmed_status(self):
        """Invariant: Simulated evidence must NEVER produce a Confirmed status."""
        evidence = [_make_evidence(ProvenanceEnum.SIMULATED, is_simulated=True)]
        finding = classify(
            evidence_records=evidence,
            title="Simulated Attempted Confirmed",
            description="Trying to force confirmed on simulation",
            severity=SeverityEnum.CRITICAL,
            run_id=1,
            authorization_failure_confirmed=True,  # Even with flag True
        )
        assert finding is not None
        assert finding.verification_status != VerificationStatus.CONFIRMED
        assert finding.verification_status == VerificationStatus.SIMULATED


class TestFindingSummaries:
    """Verifies summaries do NOT generate numeric scores or certified claims."""

    def test_summary_structure(self):
        f1 = Finding(
            run_id=1,
            title="F1",
            severity=SeverityEnum.CRITICAL,
            confidence=ConfidenceEnum.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )
        f2 = Finding(
            run_id=1,
            title="F2",
            severity=SeverityEnum.LOW,
            confidence=ConfidenceEnum.MEDIUM,
            verification_status=VerificationStatus.POTENTIAL,
        )
        summary = summarize([f1, f2])
        assert summary["total"] == 2
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["low"] == 1
        assert summary["by_status"]["confirmed"] == 1
        assert summary["by_status"]["potential"] == 1

        # No numeric score exists in summary
        assert "score" not in summary
        assert "rating" not in summary
        assert "certified" not in summary
