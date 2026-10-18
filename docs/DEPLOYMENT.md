# Deployment Guide

**Interactive Cybersecurity Lab** · *Learn. Test. Verify. Secure.*  
Version 1.0 · Production Deployment Documentation

---

## 1. Overview

The Interactive Cybersecurity Lab is designed for production deployment on modern cloud platforms such as **Render**, **Railway**, **Fly.io**, or **AWS / GCP / Azure** with containerized or PaaS Python runtimes backed by **PostgreSQL**.

The repository includes a ready-to-deploy [`render.yaml`](../render.yaml) blueprint configuring both the web service and the managed PostgreSQL database instance.

---

## 2. Architecture Specification

- **Web Server:** Gunicorn WSGI (`gunicorn "app:create_app()" --workers 2 --timeout 120`)
- **Runtime:** Python 3.11+
- **Database:** PostgreSQL 15+ (with connection pooling and SSL)
- **Health Check Endpoint:** `GET /health` (returns JSON status of database connectivity and runtime state)
- **Pre-deployment Hook:** `flask db upgrade` (applies Alembic database migrations automatically)

---

## 3. Environment Variables Reference

| Variable | Required | Default / Example | Purpose |
| :--- | :--- | :--- | :--- |
| `FLASK_ENV` | Yes | `production` | Selects configuration profile (`production`, `development`, `testing`). |
| `SECRET_KEY` | Yes | *(Crypto-random 32+ chars)* | Session signing and CSRF token protection. |
| `DATABASE_URL` | Yes | `postgresql://user:pass@host:5432/db` | Connection string to primary PostgreSQL database. |
| `EXTERNAL_TARGETS_ENABLED` | No | `false` | Enables or disables optional external target verification. Default `false` for safety. |
| `SESSION_LIFETIME_SECONDS` | No | `3600` | Inactivity session timeout (1 hour). |
| `LOG_LEVEL` | No | `WARNING` | Application logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `REPORT_OUTPUT_DIR` | No | `instance/reports` | Local disk directory for generated PDF/JSON report exports. |
| `ADMIN_USERNAME` | For provisioning | `sec_admin` | Initial administrator username for CLI provisioning. |
| `ADMIN_EMAIL` | For provisioning | `admin@cybersec-lab.internal` | Initial administrator email. |
| `ADMIN_PASSWORD` | For provisioning | *(Strong unique password)* | Initial administrator password. |
| `TESTER_USERNAME` | For provisioning | `sec_tester` | Initial tester username. |
| `TESTER_EMAIL` | For provisioning | `tester@cybersec-lab.internal` | Initial tester email. |
| `TESTER_PASSWORD` | For provisioning | *(Strong unique password)* | Initial tester password. |

---

## 4. Deploying to Render via Blueprint

1. **Connect Repository:**
   - Link the GitHub repository containing this codebase to your Render account.
2. **Create Blueprint Instance:**
   - In Render Dashboard, click **New** -> **Blueprint**.
   - Render automatically reads [`render.yaml`](../render.yaml) and provisions:
     - A Web Service (`cybersec-lab`) on Python 3.11.
     - A Managed PostgreSQL Database (`cybersec-lab-db`).
3. **Database Migrations:**
   - `render.yaml` specifies `preDeployCommand: flask db upgrade`, ensuring the database schema is up-to-date before traffic is directed to new instances.
4. **Initial Account Provisioning:**
   - Access the Render Web Shell or run locally pointing to the production database:
     ```bash
     python scripts/provision_accounts.py
     ```
   - Seed test definitions if needed:
     ```bash
     python scripts/seed_test_definitions.py
     ```

---

## 5. Post-Deployment Verification

1. **Health Check:**
   ```bash
   curl -i https://<your-render-url>.onrender.com/health
   ```
   Expected response:
   ```json
   {
     "status": "healthy",
     "database": "connected",
     "environment": "production"
   }
   ```
2. **Automated Readiness Check:**
   - Log in as the Tester account and navigate to `/readiness/`.
   - Click **Run Readiness Verification**.
   - Ensure all 5 system readiness gates (Database, Test Modules Registry, Presentation Sequences, Report Output Directory, Sandbox Isolation) pass green before presenting.
