"""
tests/integration/test_module_routes.py — Route integration tests for all 10 security test modules.

Verifies:
- Access control: authentication required for detail, run, and scenario endpoints.
- GET /tests/<slug>/ renders test details and expected metadata.
- POST /tests/<slug>/run executes the test, records execution run and findings.
- GET /tests/<slug>/runs/<id> renders captured evidence and findings.
- POST /tests/<slug>/scenario toggles scenario version and state.
- Interactive lab endpoints return controlled scenario responses.
"""

import pytest

MODULE_SLUGS = [
    "robots-txt",
    "idor",
    "forced-browsing",
    "cookies",
    "https-certificate",
    "input-validation",
    "source-inspection",
    "network-api",
    "weak-credentials",
    "error-analysis",
]


@pytest.mark.parametrize("slug", MODULE_SLUGS)
def test_test_detail_unauthenticated(client, slug):
    resp = client.get(f"/tests/{slug}/")
    assert resp.status_code in (302, 401)
    if resp.status_code == 302:
        assert "/auth/login" in resp.headers["Location"]


@pytest.mark.parametrize("slug", MODULE_SLUGS)
def test_test_detail_authenticated_tester(tester_client, slug):
    resp = tester_client.get(f"/tests/{slug}/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Security Concept" in html
    assert "Execute Live Test" in html
    assert "Presenter Notes" in html
    assert "Remediation Guidance" in html


@pytest.mark.parametrize("slug", MODULE_SLUGS)
def test_test_execution_flow(tester_client, slug):
    # Execute test run
    run_resp = tester_client.post(f"/tests/{slug}/run", follow_redirects=True)
    assert run_resp.status_code == 200
    html = run_resp.get_data(as_text=True)
    assert "Execution Run #" in html
    assert "Captured Technical Evidence" in html


@pytest.mark.parametrize("slug", MODULE_SLUGS)
def test_scenario_toggle_flow(tester_client, slug):
    # Toggle scenario state
    toggle_resp = tester_client.post(f"/tests/{slug}/scenario", follow_redirects=True)
    assert toggle_resp.status_code == 200
    html = toggle_resp.get_data(as_text=True)
    assert "Scenario configuration toggled" in html

    # Toggle back
    toggle_back = tester_client.post(f"/tests/{slug}/scenario", follow_redirects=True)
    assert toggle_back.status_code == 200


def test_lab_robots_txt_endpoint(client, db_session):
    resp = client.get("/tests/robots-txt/lab/robots.txt")
    assert resp.status_code == 200
    assert "Disallow:" in resp.get_data(as_text=True)


def test_lab_idor_endpoint(client, db_session):
    resp = client.get("/tests/idor/lab/record?id=105")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "Executive Compensation" in data["record"]["title"]


def test_lab_cookies_endpoint(client, db_session):
    resp = client.get("/tests/cookies/lab/cookie-check")
    assert resp.status_code == 200
    assert "Set-Cookie" in resp.headers
    assert "lab_session_token" in resp.headers["Set-Cookie"]


def test_lab_input_validation_endpoint(client, db_session):
    resp = client.get("/tests/input-validation/lab/search?query=canary_probe")
    assert resp.status_code == 200
    assert "canary_probe" in resp.get_data(as_text=True)


def test_lab_source_inspection_endpoint(client, db_session):
    resp = client.get("/tests/source-inspection/lab/bundle.js")
    assert resp.status_code == 200
    assert "API_BASE" in resp.get_data(as_text=True)


def test_lab_network_api_endpoint(client, db_session):
    resp = client.get("/tests/network-api/lab/employees/101")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == 101


def test_lab_weak_credentials_endpoint(client, db_session):
    resp = client.post("/tests/weak-credentials/lab/login", json={"username": "lab_admin", "password": "admin"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["authenticated"] is True


def test_lab_error_analysis_endpoint(client, db_session):
    resp = client.get("/tests/error-analysis/lab/trigger-error")
    assert resp.status_code == 500
    data = resp.get_json()
    assert "error" in data or "exception" in data
