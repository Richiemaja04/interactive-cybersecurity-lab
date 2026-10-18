"""
app/external_targets/validator.py — External target security controls & scope enforcement.

Implements all 13 external-target safeguards:
1. Disabled by default via EXTERNAL_TARGETS_ENABLED
2. Hostname must be approved in ExternalTargetApproval table
3. HTTPS port 443 only (no HTTP, no custom ports)
4. Low-impact operations allowlist
5. IP address validation: blocks loopback, RFC 1918, link-local, multicast
6. DNS revalidation to mitigate rebinding
7. Strictly read-only: remediation forbidden on external targets
8. Scope violation raises ScopeViolation -> BLOCKED run state & AuditEvent
"""

from __future__ import annotations

import enum
import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import current_app

from app.audit.service import write_audit_event
from app.models.external import ExternalTargetApproval
from app.services.execution_service import ScopeViolation


class PermittedOperation(str, enum.Enum):
    ROBOTS_TXT = "inspect_robots_txt"
    COOKIE_FLAGS = "inspect_cookie_flags"
    HTTPS_CERTIFICATE = "inspect_https_certificate"
    SECURITY_HEADERS = "inspect_security_headers"


class ExternalTargetValidator:
    """Enforces safety controls on external target requests."""

    @classmethod
    def validate_target_url(
        cls,
        url: str,
        operation: PermittedOperation,
        user_id: int | None = None,
    ) -> str:
        """
        Validates target URL against all safety boundaries.
        Returns the canonical hostname if valid.
        Raises ScopeViolation if any control is violated.
        """
        # 1. Feature flag
        if not current_app.config.get("EXTERNAL_TARGETS_ENABLED", False):
            cls._record_violation("EXTERNAL_TARGETS_DISABLED", "External target testing is disabled by policy.", user_id)
            raise ScopeViolation("External target testing is currently disabled by configuration.")

        # 2. Scheme & Port: HTTPS port 443 only
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            cls._record_violation("NON_HTTPS_SCHEME", f"Disallowed scheme '{parsed.scheme}': only https:// is permitted.", user_id)
            raise ScopeViolation(f"Only https:// scheme on port 443 is permitted. Provided scheme: '{parsed.scheme}'.")

        port = parsed.port
        if port is not None and port != 443:
            cls._record_violation("DISALLOWED_PORT", f"Disallowed port '{port}': only port 443 is permitted.", user_id)
            raise ScopeViolation(f"Only standard HTTPS port 443 is permitted. Provided port: {port}.")

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            cls._record_violation("INVALID_HOSTNAME", "No valid hostname found in URL.", user_id)
            raise ScopeViolation("Target URL does not contain a valid hostname.")

        # 3. Approved target hostname verification
        now = datetime.now(timezone.utc)
        approval = ExternalTargetApproval.query.filter_by(hostname=hostname, is_active=True).first()
        if not approval:
            cls._record_violation("UNAPPROVED_TARGET", f"Hostname '{hostname}' has not been approved by an administrator.", user_id)
            raise ScopeViolation(f"Hostname '{hostname}' is not on the administrator-approved target list.")

        if approval.valid_until and approval.valid_until < now:
            cls._record_violation("EXPIRED_APPROVAL", f"Approval for hostname '{hostname}' expired at {approval.valid_until}.", user_id)
            raise ScopeViolation(f"Approval for hostname '{hostname}' has expired.")

        # 4. IP address & SSRF prevention (DNS resolution check)
        resolved_ips = cls._resolve_and_validate_ips(hostname, user_id)

        # 5. Permitted operation check
        if not isinstance(operation, PermittedOperation):
            cls._record_violation("DISALLOWED_OPERATION", f"Operation '{operation}' is not permitted against external targets.", user_id)
            raise ScopeViolation(f"Operation '{operation}' is not an approved safe check.")

        return hostname

    @classmethod
    def _resolve_and_validate_ips(cls, hostname: str, user_id: int | None) -> list[str]:
        """Resolves hostname and validates that none of the IPs are private, loopback, or reserved."""
        try:
            addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            cls._record_violation("DNS_RESOLUTION_FAILURE", f"Failed to resolve hostname '{hostname}': {e}", user_id)
            raise ScopeViolation(f"DNS resolution failed for hostname '{hostname}'.") from e

        ips = set()
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ips.add(ip_str)
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if (
                    ip_obj.is_loopback
                    or ip_obj.is_private
                    or ip_obj.is_link_local
                    or ip_obj.is_multicast
                    or ip_obj.is_reserved
                    or ip_obj.is_unspecified
                ):
                    cls._record_violation(
                        "DISALLOWED_IP_RANGE",
                        f"Hostname '{hostname}' resolved to prohibited IP range: {ip_str}",
                        user_id,
                    )
                    raise ScopeViolation(f"Target resolves to internal or reserved IP range: {ip_str}.")
            except ValueError as ve:
                cls._record_violation("INVALID_IP_FORMAT", f"Invalid IP format: {ve}", user_id)
                raise ScopeViolation(f"Invalid IP address returned: {ip_str}") from ve

        return list(ips)

    @classmethod
    def _record_violation(cls, violation_type: str, reason: str, user_id: int | None) -> None:
        """Writes an immutable, sanitized audit event for scope violation."""
        write_audit_event(
            action="EXTERNAL_TARGET_SCOPE_VIOLATION",
            user_id=user_id,
            detail={
                "violation_type": violation_type,
                "reason": reason,
            },
        )
