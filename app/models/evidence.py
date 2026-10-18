"""
app/models/evidence.py — Evidence records with provenance tracking.

Evidence is stored as labelled, sanitized extracted fields.
Raw HTTP bodies are never stored.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from app.extensions import db


class ProvenanceEnum(str, enum.Enum):
    OBSERVED_LIVE = "observed_live"
    CONTROLLED_SCENARIO = "controlled_scenario"
    SIMULATED = "simulated"
    MANUALLY_VERIFIED = "manually_verified"


class EvidenceType(str, enum.Enum):
    HTTP_RESPONSE = "http_response"
    COOKIE_ATTRIBUTES = "cookie_attributes"
    CERTIFICATE_DETAILS = "certificate_details"
    PAGE_SOURCE_EXCERPT = "page_source_excerpt"
    API_RESPONSE_FIELDS = "api_response_fields"
    ERROR_MESSAGE = "error_message"
    HEADER_INSPECTION = "header_inspection"
    CREDENTIAL_TEST = "credential_test"
    URL_PARAMETER = "url_parameter"
    FORM_REFLECTION = "form_reflection"
    OBSERVATION = "observation"


class EvidenceRecord(db.Model):
    """
    Sanitized, labelled evidence collected during test execution.

    Provenance must be set accurately — it drives finding classification:
    - SIMULATED evidence → finding.verification_status = Simulated
    - OBSERVED_LIVE with authorization failure → may be Confirmed
    """

    __tablename__ = "evidence_records"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(
        db.Integer,
        db.ForeignKey("execution_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provenance = db.Column(
        db.Enum(ProvenanceEnum, name="provenance_enum"),
        nullable=False,
        index=True,
    )
    evidence_type = db.Column(
        db.Enum(EvidenceType, name="evidence_type_enum"),
        nullable=False,
    )
    # Sanitized detail fields — no credentials, stack traces, or internal paths
    title = db.Column(db.String(256), nullable=False)
    sanitized_detail = db.Column(db.JSON, nullable=False, default=dict)
    observation = db.Column(db.Text, nullable=True)          # Human-readable interpretation
    is_simulated = db.Column(db.Boolean, nullable=False, default=False)
    collected_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    run = db.relationship("ExecutionRun", back_populates="evidence_records")

    def __repr__(self) -> str:
        return (
            f"<EvidenceRecord run={self.run_id} "
            f"type={self.evidence_type.value} "
            f"provenance={self.provenance.value}>"
        )
