"""
tests/integration/test_rehearsal.py — Rehearsal mode and fault injection tests.
"""

from app.models.rehearsal import FaultInjection, FaultType, RehearsalSession


def test_rehearsal_session_lifecycle(tester_client, tester_user, db_session):
    # 1. Start rehearsal session
    start_resp = tester_client.post("/rehearsal/start", follow_redirects=True)
    assert start_resp.status_code == 200
    assert "REHEARSAL SESSION #" in start_resp.get_data(as_text=True)

    session = RehearsalSession.query.filter_by(user_id=tester_user.id, is_active=True).first()
    assert session is not None

    # 2. Toggle fault on
    toggle_resp = tester_client.post(
        "/rehearsal/toggle-fault",
        data={"fault_type": "controlled_timeout"},
        follow_redirects=True,
    )
    assert toggle_resp.status_code == 200
    assert "SIMULATED FAULT ACTIVE" in toggle_resp.get_data(as_text=True)

    fault = FaultInjection.query.filter_by(
        rehearsal_session_id=session.id,
        fault_type=FaultType.CONTROLLED_TIMEOUT,
    ).first()
    assert fault is not None
    assert fault.is_enabled is True

    # 3. End rehearsal session
    end_resp = tester_client.post("/rehearsal/end", follow_redirects=True)
    assert end_resp.status_code == 200
    assert "Rehearsal session ended" in end_resp.get_data(as_text=True)

    # Confirm session ended and fault cleared
    db_session.refresh(session)
    assert session.is_active is False
    db_session.refresh(fault)
    assert fault.is_enabled is False
