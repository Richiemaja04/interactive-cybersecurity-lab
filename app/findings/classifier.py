"""
app/findings/classifier.py — Finding classification engine.

Rules (in priority order):
1. All evidence SIMULATED → VerificationStatus.SIMULATED
2. Any SIMULATED mixed with live (live not definitive) → INCONCLUSIVE
3. OBSERVED_LIVE with confirmed authorization failure → CONFIRMED
4. OBSERVED_LIVE but ambiguous → POTENTIAL
5. No evidence → returns None (no finding)

Invariants:
- Simulated evidence NEVER produces a CONFIRMED finding.
- No overall security score is computed.
- No "certified secure" claim is ever made.
"""

from __future__ import annotations

from app.models.evidence import EvidenceRecord, ProvenanceEnum
from app.models.finding import ConfidenceEnum, Finding, SeverityEnum, VerificationStatus


def classify(
    evidence_records: list[EvidenceRecord],
    title: str,
    description: str,
    severity: SeverityEnum,
    run_id: int,
    *,
    authorization_failure_confirmed: bool = False,
) -> Finding | None:
    """
    Classify a list of evidence records into a Finding.
    Returns None if the list is empty (no finding).
    """
    if not evidence_records:
        return None

    provenances = {r.provenance for r in evidence_records}
    has_simulated = ProvenanceEnum.SIMULATED in provenances
    has_live = ProvenanceEnum.OBSERVED_LIVE in provenances
    has_controlled = ProvenanceEnum.CONTROLLED_SCENARIO in provenances

    # ── Determine verification status ─────────────────────────────────────────
    if has_simulated and not has_live and not has_controlled:
        status = VerificationStatus.SIMULATED
        confidence = ConfidenceEnum.UNKNOWN

    elif has_simulated and (has_live or has_controlled) and not authorization_failure_confirmed:
        status = VerificationStatus.INCONCLUSIVE
        confidence = ConfidenceEnum.LOW

    elif has_live and authorization_failure_confirmed:
        status = VerificationStatus.CONFIRMED
        confidence = ConfidenceEnum.HIGH

    elif has_controlled and not has_simulated:
        # Controlled scenario without explicit live confirmation
        status = VerificationStatus.POTENTIAL
        confidence = ConfidenceEnum.MEDIUM

    else:
        status = VerificationStatus.POTENTIAL
        confidence = ConfidenceEnum.LOW

    finding = Finding(
        run_id=run_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        verification_status=status,
    )
    return finding


def summarize(findings: list[Finding]) -> dict:
    """
    Produce a dashboard summary of findings.
    No overall score — never claims certification.
    """
    if not findings:
        return {
            "total": 0,
            "by_severity": {},
            "by_status": {},
            "has_confirmed": False,
        }

    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        by_status[f.verification_status.value] = by_status.get(f.verification_status.value, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_status": by_status,
        "has_confirmed": any(
            f.verification_status == VerificationStatus.CONFIRMED for f in findings
        ),
    }
