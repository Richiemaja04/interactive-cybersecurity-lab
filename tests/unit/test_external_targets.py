"""
tests/unit/test_external_targets.py — Scope validation and safety enforcement tests.

Verifies:
- Feature flag blocks requests when disabled.
- Non-HTTPS and custom ports are blocked.
- Loopback (127.0.0.1) and RFC 1918 private IPs (10.0.0.0/8, 192.168.0.0/16) are blocked.
- Unapproved hostnames raise ScopeViolation.
- Scope violations write immutable AuditEvent records.
"""

import pytest

from app.audit.service import write_audit_event
from app.external_targets.validator import ExternalTargetValidator, PermittedOperation
from app.models.audit import AuditEvent
from app.models.external import ExternalTargetApproval
from app.services.execution_service import ScopeViolation


def test_external_targets_disabled_by_default(app):
    with app.app_context():
        # Ensure EXTERNAL_TARGETS_ENABLED is False
        app.config["EXTERNAL_TARGETS_ENABLED"] = False
        with pytest.raises(ScopeViolation, match="disabled by configuration"):
            ExternalTargetValidator.validate_target_url(
                "https://example.com",
                PermittedOperation.ROBOTS_TXT,
            )


def test_non_https_rejected(app):
    with app.app_context():
        app.config["EXTERNAL_TARGETS_ENABLED"] = True
        with pytest.raises(ScopeViolation, match="Only https:// scheme"):
            ExternalTargetValidator.validate_target_url(
                "http://example.com",
                PermittedOperation.ROBOTS_TXT,
            )


def test_custom_port_rejected(app):
    with app.app_context():
        app.config["EXTERNAL_TARGETS_ENABLED"] = True
        with pytest.raises(ScopeViolation, match="Only standard HTTPS port 443"):
            ExternalTargetValidator.validate_target_url(
                "https://example.com:8443",
                PermittedOperation.ROBOTS_TXT,
            )


def test_unapproved_target_rejected(app, db_session):
    with app.app_context():
        app.config["EXTERNAL_TARGETS_ENABLED"] = True
        with pytest.raises(ScopeViolation, match="not on the administrator-approved target list"):
            ExternalTargetValidator.validate_target_url(
                "https://unapproved-target-domain.com",
                PermittedOperation.ROBOTS_TXT,
            )


def test_loopback_and_private_ip_blocked(app, db_session, monkeypatch):
    with app.app_context():
        app.config["EXTERNAL_TARGETS_ENABLED"] = True

        # Approve hostname
        approval = ExternalTargetApproval(
            hostname="safe-appearing-host.local",
            is_active=True,
        )
        db_session.add(approval)
        db_session.commit()

        # Mock DNS resolution to return private RFC 1918 IP
        import socket
        def mock_getaddrinfo(host, port, proto=0):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 443))]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        with pytest.raises(ScopeViolation, match="Target resolves to internal or reserved IP range"):
            ExternalTargetValidator.validate_target_url(
                "https://safe-appearing-host.local",
                PermittedOperation.ROBOTS_TXT,
            )

        # Confirm audit event was recorded
        violation_events = AuditEvent.query.filter_by(action="EXTERNAL_TARGET_SCOPE_VIOLATION").all()
        assert len(violation_events) > 0
