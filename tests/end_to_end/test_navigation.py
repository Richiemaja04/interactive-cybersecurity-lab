"""
tests/end_to_end/test_navigation.py — End-to-end navigation, sequences, and readiness checks.
"""

from app.models.preset import PresentationSequence
from app.presentation_sequences.routes import ensure_default_sequence
from scripts.seed_test_definitions import TEST_DEFINITIONS


def test_landing_page(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Interactive Cybersecurity Lab" in html
    assert "Learn. Test. Verify. Secure." in html
    assert "Safe-Testing Principles" in html


def test_readiness_check_endpoint(client, db_session):
    resp = client.get("/readiness/check")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "overall_status" in data
    assert "can_proceed" in data
    assert len(data["checks"]) >= 4


def test_guided_presentation_navigation(tester_client, db_session):
    # Ensure sequence exists
    seq = ensure_default_sequence()

    # View sequence index
    idx_resp = tester_client.get("/sequences/")
    assert idx_resp.status_code == 200
    assert "Standard 10-Check Browser Security Walkthrough" in idx_resp.get_data(as_text=True)

    # Walk through first 3 steps
    for step_num in range(1, 4):
        step_resp = tester_client.get(f"/sequences/{seq.id}?step={step_num}")
        assert step_resp.status_code == 200
        html = step_resp.get_data(as_text=True)
        assert f"STEP {step_num} OF 10" in html
        assert "Presenter Notes" in html


import html as html_lib


def test_all_ten_test_pages_accessible(tester_client):
    for td in TEST_DEFINITIONS:
        resp = tester_client.get(f"/tests/{td['slug']}/")
        assert resp.status_code == 200
        page_html = resp.get_data(as_text=True)
        assert (td["name"] in page_html) or (html_lib.escape(td["name"]) in page_html)
        assert "Execute Live Test" in page_html
