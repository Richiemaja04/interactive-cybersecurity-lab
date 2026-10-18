"""
scripts/seed_test_definitions.py — Seed the ten test definitions.

Run after the first migration to populate TestDefinition rows.
These are source-of-truth definitions from the Web Security Testing presentation.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models.scenario import TestDefinition

TEST_DEFINITIONS = [
    {
        "number": "01",
        "name": "Robots.txt Enumeration",
        "slug": "robots-txt",
        "category": "Information disclosure",
        "objective": "Demonstrate that a publicly readable robots.txt may disclose application paths but does not enforce access control.",
        "concept": "robots.txt is a convention, not a security boundary. Paths listed as disallowed are still reachable by anyone who requests them directly.",
        "presenter_notes": "Show students that robots.txt is public. Then demonstrate that a disallowed path can still be fetched directly. Emphasize: security by obscurity is not access control.",
    },
    {
        "number": "02",
        "name": "URL Parameter Tampering & IDOR",
        "slug": "idor",
        "category": "Authorization and access control",
        "objective": "Use synthetic records to demonstrate object-level authorization. Show that changing an identifier must not grant access to another user's record.",
        "concept": "Insecure Direct Object Reference (IDOR) occurs when object identifiers are user-controlled and the server does not verify ownership. Observation of an unexpected response does not automatically confirm a vulnerability — further validation is required.",
        "presenter_notes": "Switch between record IDs. Show the vulnerable path (no ownership check) and the secure path (ownership enforced). Remind students that this is a controlled lab — only synthetic records are used.",
    },
    {
        "number": "03",
        "name": "Directory Guessing / Forced Browsing",
        "slug": "forced-browsing",
        "category": "Resource protection",
        "objective": "Check a small, fixed set of approved demonstration paths. Explain why hidden URLs are not a security boundary and verify authorization behavior.",
        "concept": "Forced browsing tests whether unlisted or unlinked paths are protected by authorization, not just hidden from navigation. A 404 is not equivalent to a 403.",
        "presenter_notes": "Walk through three approved demo paths. Compare 200 (no auth), 403 (auth enforced), and 404 (not found). Discuss the difference between obscurity and access control.",
    },
    {
        "number": "04",
        "name": "Cookie Inspection",
        "slug": "cookies",
        "category": "Session security",
        "objective": "Demonstrate the purpose and behavior of HttpOnly, Secure, and SameSite cookie attributes.",
        "concept": "Cookie flags protect session tokens from JavaScript access (HttpOnly), interception over HTTP (Secure), and cross-site request forgery (SameSite). Missing flags are observations requiring validation — not automatic confirmed vulnerabilities.",
        "presenter_notes": "Use browser DevTools to inspect the Set-Cookie header. Toggle between the vulnerable (no flags) and secure (all flags set) scenarios. Explain what each flag prevents.",
    },
    {
        "number": "05",
        "name": "HTTPS & Certificate Check",
        "slug": "https-certificate",
        "category": "Transport security",
        "objective": "Demonstrate HTTPS enforcement, certificate trust/validity where reliably observable, and the distinction between transport security and application security.",
        "concept": "HTTPS encrypts data in transit but does not guarantee application-layer security. An expired or untrusted certificate prevents the browser from establishing a secure channel. HTTP without redirect is a transport exposure.",
        "presenter_notes": "Show the browser's certificate details. Demonstrate HTTP-to-HTTPS redirect. Clarify that HTTPS does not mean the application is secure — only the transport layer.",
    },
    {
        "number": "06",
        "name": "Form Input Validation & XSS Awareness",
        "slug": "input-validation",
        "category": "Input handling",
        "objective": "Use harmless strings to demonstrate input handling, reflection, output encoding, and controlled validation errors. Do not execute dangerous payloads.",
        "concept": "XSS occurs when user input is reflected into a page without output encoding. Client-side validation alone is insufficient. CSP headers provide an additional layer. Harmless test strings are used — no live attack payloads.",
        "presenter_notes": "Submit a harmless test string (e.g., a plain <script> tag as text). Show the vulnerable (unencoded reflection) and secure (encoded output) scenarios. Emphasize: we use harmless strings only.",
    },
    {
        "number": "07",
        "name": "Inspect Page Source & Client-Side Code",
        "slug": "source-inspection",
        "category": "Information exposure",
        "objective": "Demonstrate that delivered client-side code is visible to the user. Use synthetic examples to distinguish public configuration from actual secret exposure.",
        "concept": "Anything delivered to the browser is readable by the user. API keys, internal service URLs, and credentials must never appear in client-side code. This module uses synthetic examples only — no real secrets are ever used.",
        "presenter_notes": "View page source. Point to the synthetic 'exposed' key in the vulnerable scenario. Then show the secure scenario where only public configuration appears. Remind the audience: we never use real secrets in this lab.",
    },
    {
        "number": "08",
        "name": "Network Tab: What Is the Site Sending?",
        "slug": "network-api",
        "category": "API responses and data exposure",
        "objective": "Demonstrate API response inspection and compare displayed UI data with returned data. Show the importance of server-side authorization and data minimization.",
        "concept": "APIs often return more data than the UI displays. Unnecessary fields may expose internal IDs, PII, or business logic. Server-side authorization must restrict what each user can retrieve — the UI hiding a field is not protection.",
        "presenter_notes": "Open the Network tab and inspect the API response for a synthetic record. Show the overshared (vulnerable) vs. minimized (secure) response. Discuss data minimization.",
    },
    {
        "number": "09",
        "name": "Default & Weak Credential Testing",
        "slug": "weak-credentials",
        "category": "Authentication",
        "objective": "Use only purpose-built lab accounts and predefined credentials. Demonstrate authentication controls without performing credential guessing against real services.",
        "concept": "Default credentials (admin/admin, admin/password) remain one of the most common authentication failures. This test uses purpose-built lab accounts only. No external credential guessing is performed.",
        "presenter_notes": "Log in with the weak lab credential (admin/admin). Show successful access in the vulnerable scenario. Show lockout or rejection in the secure scenario. Emphasize: lab accounts only, never real systems.",
    },
    {
        "number": "10",
        "name": "Error Message Analysis",
        "slug": "error-analysis",
        "category": "Information leakage",
        "objective": "Trigger safe errors and demonstrate the difference between helpful user-facing messages and sensitive implementation details exposed in error responses.",
        "concept": "Verbose error messages may disclose stack traces, file paths, database queries, framework versions, and internal hostnames. Sanitized error messages protect these details while still being helpful to legitimate users.",
        "presenter_notes": "Trigger a safe error (invalid input, missing record). Show the verbose response (vulnerable) with stack trace or path. Show the sanitized response (secure). Discuss what each piece of information enables for an attacker.",
    },
]


def main():
    app = create_app()
    with app.app_context():
        added = 0
        for td_data in TEST_DEFINITIONS:
            existing = TestDefinition.query.filter_by(number=td_data["number"]).first()
            if existing:
                print(f"Test {td_data['number']} already exists — skipping.")
                continue
            td = TestDefinition(**td_data)
            db.session.add(td)
            added += 1
        db.session.commit()
        print(f"Seeded {added} test definitions.")


if __name__ == "__main__":
    main()
