# Interactive Cybersecurity Lab

**Learn. Test. Verify. Secure.**

An interactive, presentation-ready cybersecurity training platform that reproduces ten browser-based web security checks, demonstrates vulnerable versus secure behavior, captures sanitized forensic evidence, and teaches users to verify remediation safely.

---

## 1. Overview & Architecture

The **Interactive Cybersecurity Lab** is a full-stack Python Flask application built on PostgreSQL and vanilla CSS. It bridges the gap between static vulnerability descriptions and hands-on comprehension by providing:

- **10 Core Security Checks:** Derived directly from browser-based web security testing methodology.
- **Controlled Lab Sandbox:** Intentionally vulnerable demonstration endpoints (`/tests/<slug>/lab/`) isolated completely from platform management and administrative interfaces.
- **Provenance-Driven Evidence:** Strict classification into `Confirmed`, `Potential`, `Simulated`, and `Inconclusive` states. **Simulated evidence can never produce a Confirmed status.**
- **Safe-Testing Principles:** No weaponized exploits, no destructive commands, no public self-registration, and strict RFC 1918 private IP blocking for optional external testing.
- **No Deceptive Scoring:** Strictly avoids subjective numeric security scores or misleading "certified secure" claims.

```
                              [ Browser Client ]
                                      |
                      (HTTPS / CSRF Protection / CSP)
                                      v
                        +---------------------------+
                        |     Flask Application     |
                        |      (Application)        |
                        +-------------+-------------+
                                      |
         +----------------------------+----------------------------+
         |                            |                            |
         v                            v                            v
  [ Auth & Admin ]            [ Test Modules ]            [ Reports & Presets ]
  - CLI Provisioning          - 10 Checks                 - PDF (ReportLab)
  - RBAC (Admin/Tester)       - Execution State Machine   - JSON Export
  - Immutable Audit Log       - Evidence Sanitization     - Schema Validation
  - Retention Purge Engine    - Atomic Remediation Engine - Incident Response
```

---

## 2. The Ten Security Checks

| # | Slug | Check Name | Category | Primary Focus |
|---|---|---|---|---|
| 01 | `robots-txt` | Robots.txt Enumeration | Information Disclosure | Proves `robots.txt` is an indexing convention, not an access control boundary. |
| 02 | `idor` | URL Parameter Tampering & IDOR | Authorization & Access Control | Demonstrates object-level authorization using synthetic records without leakage. |
| 03 | `forced-browsing` | Directory Guessing / Forced Browsing | Resource Protection | Distinguishes between obscurity (hidden links) and real authorization checks. |
| 04 | `cookies` | Cookie Inspection | Session Security | Analyzes missing `HttpOnly`, `Secure`, and `SameSite` flags and demonstrates fix. |
| 05 | `https-certificate` | HTTPS & Certificate Check | Transport Security | Inspects TLS protocols, cipher suites, expiration, and common name alignment. |
| 06 | `input-validation` | Form Input Validation & Reflection | Client-Side Security | Validates client/server boundary enforcement and benign reflection defense. |
| 07 | `source-inspection` | Source Code Inspection | Information Disclosure | Identifies developer comments, hardcoded API endpoints, and test flags. |
| 08 | `network-api` | Network Traffic & API Over-fetching | Authorization & API Design | Demonstrates excessive data exposure in REST API payloads vs. filtered output. |
| 09 | `weak-credentials` | Default & Weak Credentials | Authentication | Verifies lockout policies and resistance to known credential stuffing lists. |
| 10 | `error-analysis` | Error Message Analysis | Defense in Depth | Contrasts verbose stack traces and SQL debug info with sanitized generic errors. |

---

## 3. Key Capabilities

### A. Lifecycle State Machine & Evidence Sanitization
- Every test run progresses through explicit lifecycle states: `QUEUED` -> `RUNNING` -> `COMPLETED` / `FAILED` / `BLOCKED`.
- Sensitive tokens, passwords, session identifiers, and PII in captured request/response bodies are automatically redacted by the `EvidenceSanitizer` before storage.

### B. Atomic Remediation Engine with Optimistic Locking
- Tests feature toggleable scenarios (`vulnerable` vs. `secure`).
- Remediation actions track version numbers (`expected_version`). Concurrent or stale actions are rejected with a `StaleActionError`.
- Every remediation captures exact before-and-after states atomically and logs an entry to the immutable `RemediationAudit` log.
- Remediations can be reversed on-demand for repeated instructional walkthroughs.

### C. Presentation Sequences & Notes Drawer
- Built-in guided walkthrough mode stepping through all 10 checks sequentially.
- Presenter notes drawer with slide controls, timing advice, demonstration tips, and keyboard navigation.

### D. Automated Pre-Demo Readiness Verification Gate
- Automated pre-flight checks at `/readiness/` verify:
  1. Database connectivity and read/write availability.
  2. All 10 test modules correctly loaded and registered.
  3. Default presentation sequence populated and intact.
  4. Report export directory writable and permissions intact.
  5. Isolated sandbox routes returning expected synthetic baselines.

### E. Professional Reporting & Presets
- PDF report export generated via ReportLab with executive summary, methodology, provenance details, and evidence breakdown.
- Machine-readable JSON exports conforming to strict schema specifications.
- Presets system allowing exporting and importing test configurations and scenarios with transactional rollback on validation failure.

### F. Incident Response Walkthrough
- 5-step interactive incident response module:
  1. Triage & Classification
  2. Containment
  3. Evidence Preservation
  4. Eradication & Remediation
  5. Post-Incident Review & Hardening

### G. Security Boundaries & Safeguards
- **Zero Public Self-Registration:** Accounts are provisioned strictly via CLI.
- **SSRF & Private IP Blocking:** External target checks block RFC 1918 addresses, loopbacks, and link-local ranges with DNS rebinding defenses.
- **90-Day Retention Purge Engine:** Automated deletion of historical runs and evidence with cryptographic hash recording of purged batches.
- **Rehearsal & Fault Injection:** Practice mode with simulated network drops, rate limits, and server error injections.

---

## 4. Getting Started

### Prerequisites
- Python 3.11+
- PostgreSQL 15+ (or SQLite for quick local development)
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/interactive-cybersecurity-lab.git
   cd interactive-cybersecurity-lab
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   # Windows:
   .\.venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your database URL, secret key, and initial admin/tester credentials
   ```

5. **Initialize database & apply migrations:**
   ```bash
   flask db upgrade
   ```

6. **Seed test definitions & provision initial accounts:**
   ```bash
   python scripts/seed_test_definitions.py
   python scripts/provision_accounts.py
   ```

7. **Start the local development server:**
   ```bash
   flask run --port 5000
   ```
   Navigate to `http://127.0.0.1:5000` in your browser.

---

## 5. Testing & Quality Assurance

The codebase includes comprehensive test suites spanning unit, integration, security access control, and end-to-end user navigation:

```bash
# Run the complete test suite (172+ tests)
pytest

# Run tests with code coverage report
pytest --cov=app --cov-report=term-missing

# Run specific test suites
pytest tests/unit/
pytest tests/integration/
pytest tests/security/
pytest tests/end_to_end/
```

**Quality Metrics:**
- **Tests:** 172 passed, 0 failures.
- **Code Coverage:** >85% across entire application.
- **Security Tests:** Full RBAC and authorization verification for every endpoint.

---

## 6. Deployment

Production deployment is fully supported on Render, Railway, Fly.io, or traditional container environments.

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for complete step-by-step instructions.

---

## 7. Educational & Safety Disclaimer

This application is created strictly for cybersecurity education, presentation, and remediation verification. All intentionally vulnerable behaviors are restricted to sandboxed lab endpoints and execute with synthetic data.

Never execute security testing against systems, networks, or applications without explicit, written authorization from the system owner.
