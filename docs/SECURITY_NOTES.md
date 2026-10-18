# Security Notes & Architecture Safeguards

**Interactive Cybersecurity Lab** · *Learn. Test. Verify. Secure.*  
Version 1.0 · Application Security Documentation

---

## 1. Threat Model & Sandboxing Architecture

The Interactive Cybersecurity Lab demonstrates intentionally vulnerable behaviors for educational and verification purposes. To ensure these intentionally vulnerable demonstrations cannot be leveraged to compromise the host system, the underlying application, or external third-party infrastructure, the application implements strict defense-in-depth isolation boundaries.

```
+-------------------------------------------------------------------------+
|                              Host Browser                               |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  Platform Boundary (Flask + Werkzeug)                   |
|  - Role-based Access Control (Flask-Login + Custom Decorators)          |
|  - CSRF Protection (Flask-WTF SeaSurf / Tokens)                         |
|  - Strict Content-Security-Policy & Secure Headers                      |
+------------------------------------+------------------------------------+
                   |                                      |
                   v                                      v
+--------------------------------------+   +------------------------------+
| Core Platform Services               |   | Lab Sandbox Endpoints        |
| - Authentication & Provisioning      |   | - /tests/<slug>/lab/...      |
| - Immutable Audit Logging            |   | - Purely Synthetic Records   |
| - Presentation Sequences             |   | - Isolated In-Memory State   |
| - PDF/JSON Report Engine             |   | - Benign Payloads Only       |
+--------------------------------------+   +------------------------------+
```

---

## 2. Intentional Vulnerability Isolation

1. **Dedicated Route Namespaces:**
   - All intentionally vulnerable endpoints reside exclusively under the `/tests/<slug>/lab/` namespace.
   - Core administrative endpoints (`/admin/`), audit logs (`/audit/`), sequence management (`/sequences/`), and report downloads (`/reports/`) are governed by separate controllers and enforce strict `@role_required(RoleEnum.ADMINISTRATOR)` authorization.

2. **Synthetic Demonstration Data Only:**
   - Demonstrations of IDOR (URL Parameter Tampering) query synthetic mock profiles (`rec-101`, `rec-102`, `rec-103`) containing fictitious names, addresses, and account numbers.
   - Real user credentials, session tokens, and database passwords are never referenced or returned in lab endpoints.

3. **Benign Payloads Only:**
   - XSS and Input Validation demonstrations utilize non-destructive tokens (e.g., `<b>Safe bold test</b>`, `<script>console.log("Safe lab token")</script>`).
   - Weaponized exploits, remote file inclusions, SQL injection worms, or destructive commands are prohibited by design.

---

## 3. Provenance-Driven Evidence & Classification Rules

The lab enforces strict classification semantics to ensure testing outcomes are scientifically accurate and non-misleading:

| Status | Verification Rule |
| :--- | :--- |
| **Confirmed** | A security control failure was directly observed under live, controlled execution conditions. **Simulated evidence can NEVER produce a Confirmed status.** |
| **Potential** | Indicators suggest an anomaly or missing security control, but secondary confirmation was not established. |
| **Simulated** | Evidence was generated via controlled mock or simulation scenarios rather than live socket/protocol observation. |
| **Inconclusive** | Execution encountered network timeouts, unreachable sockets, or indeterminate responses. |

**Important Safety Principle:** The platform strictly prohibits presenting arbitrary overall numeric scores (e.g. "82/100") or issuing deceptive "Certified Secure" seals.

---

## 4. External Target Testing Safeguards

When `EXTERNAL_TARGETS_ENABLED=true` is explicitly configured by an administrator:

1. **Administrative Approval Required:**
   - Targets must be pre-approved with an active approval record in the database before requests are dispatched.
2. **Protocol & Port Enforcement:**
   - Only `https://` schemes on port `443` are permitted.
3. **Private IP & Loopback Blocking (SSRF Prevention):**
   - RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are blocked.
   - Loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and carrier-grade NAT ranges are blocked.
   - DNS resolution is performed prior to socket connection to verify resolved IP addresses against blocklists (DNS rebinding defense).
4. **Read-Only HTTP Methods:**
   - Only `GET` and `HEAD` requests are permitted. State-modifying requests (`POST`, `PUT`, `DELETE`, `PATCH`) are disallowed.
5. **Auditing:**
   - Every external target verification attempt, whether permitted or blocked, writes an immutable record to the `AuditEvent` log.

---

## 5. Remediation Integrity & Concurrency Controls

1. **Optimistic Locking (`expected_version`):**
   - Remediation actions track scenario version numbers. If an action is attempted against an out-of-date scenario state, a `StaleActionError` is raised and the transaction is aborted.
2. **Atomic Transitions:**
   - Remediation actions capture exact before-and-after states atomically within a single database transaction.
3. **Reversal Capability:**
   - Applied remediations can be rolled back to their vulnerable state for re-demonstration while preserving a complete audit trail in `RemediationAudit`.

---

## 6. Access Control & Account Provisioning

1. **Zero Public Self-Registration:**
   - There are no public signup or registration routes.
   - All user accounts are provisioned exclusively via the command-line script `scripts/provision_accounts.py` using secure environment variables.
2. **Role Hierarchy:**
   - **Anonymous:** Access to landing page, documentation, and safe public resources.
   - **Tester:** Access to test executions, lab scenarios, guided sequence walkthroughs, and report generation.
   - **Administrator:** Full access including user administration, audit log inspection, retention purge configuration, fault injection, and external target approvals.
3. **Session Security:**
   - Sessions are secured with `HttpOnly`, `SameSite=Lax`, and `Secure` cookie attributes in production.
   - Inactivity timeouts default to 3600 seconds (1 hour).
