"""
app/tests/registry.py — Test module registry.

Provides singleton instances and lookup for all 10 security test modules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.tests._base import SecurityTestModule

from app.tests.robots_txt.module import RobotsTxtModule
from app.tests.idor.module import IdorModule
from app.tests.forced_browsing.module import ForcedBrowsingModule
from app.tests.cookies.module import CookiesModule
from app.tests.https_certificate.module import HttpsCertificateModule
from app.tests.input_validation.module import InputValidationModule
from app.tests.source_inspection.module import SourceInspectionModule
from app.tests.network_api.module import NetworkApiModule
from app.tests.weak_credentials.module import WeakCredentialsModule
from app.tests.error_analysis.module import ErrorAnalysisModule

_MODULES_BY_SLUG: dict[str, SecurityTestModule] = {
    "robots-txt": RobotsTxtModule(),
    "idor": IdorModule(),
    "forced-browsing": ForcedBrowsingModule(),
    "cookies": CookiesModule(),
    "https-certificate": HttpsCertificateModule(),
    "input-validation": InputValidationModule(),
    "source-inspection": SourceInspectionModule(),
    "network-api": NetworkApiModule(),
    "weak-credentials": WeakCredentialsModule(),
    "error-analysis": ErrorAnalysisModule(),
}

_MODULES_BY_NUMBER: dict[str, SecurityTestModule] = {
    m.test_id: m for m in _MODULES_BY_SLUG.values()
}


def get_module_by_slug(slug: str) -> SecurityTestModule | None:
    """Return the SecurityTestModule for a given test slug, or None if unknown."""
    return _MODULES_BY_SLUG.get(slug)


def get_module_by_number(number: str) -> SecurityTestModule | None:
    """Return the SecurityTestModule for a given test number ('01'-'10')."""
    return _MODULES_BY_NUMBER.get(number)


def get_all_modules() -> dict[str, SecurityTestModule]:
    """Return a mapping of all registered modules keyed by slug."""
    return dict(_MODULES_BY_SLUG)
