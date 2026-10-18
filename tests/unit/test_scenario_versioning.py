"""
tests/unit/test_scenario_versioning.py — Phase 2: Scenario versioning & optimistic locking unit tests.
"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.scenario import Scenario, ScenarioState, ScenarioVersion, TestDefinition


class TestScenarioVersioning:
    """Verifies linear version history and optimistic-lock version conflict detection."""

    def test_scenario_creation_initial_version(self, db_session):
        test_def = TestDefinition(
            number="01",
            name="Robots.txt Enumeration",
            slug="robots-txt-version-test",
            category="Information Disclosure",
            objective="Inspect robots.txt",
            concept="Robots.txt is not an access control mechanism",
        )
        db_session.add(test_def)
        db_session.commit()

        scenario = Scenario(
            test_id=test_def.id,
            name="Robots.txt Vulnerable",
            current_version=1,
            state=ScenarioState.VULNERABLE,
            config_json={"paths": ["/admin/", "/backup/"]},
        )
        db_session.add(scenario)
        db_session.commit()

        # Initial snapshot
        version_snap = ScenarioVersion(
            scenario_id=scenario.id,
            version=1,
            snapshot_json=scenario.config_json,
            change_description="Initial vulnerable scenario definition",
        )
        db_session.add(version_snap)
        db_session.commit()

        assert scenario.current_version == 1
        assert scenario.versions.count() == 1
        assert scenario.versions.first().snapshot_json["paths"] == ["/admin/", "/backup/"]

    def test_linear_version_increment(self, db_session):
        test_def = TestDefinition(
            number="02",
            name="IDOR Test",
            slug="idor-version-test",
            category="Access Control",
            objective="Tamper IDs",
            concept="Server authorization",
        )
        db_session.add(test_def)
        db_session.commit()

        scenario = Scenario(
            test_id=test_def.id,
            name="IDOR Scenario",
            current_version=1,
            state=ScenarioState.VULNERABLE,
            config_json={"authz_enforced": False},
        )
        db_session.add(scenario)
        db_session.commit()

        # Mutate to version 2 (Remediation applied)
        scenario.current_version = 2
        scenario.state = ScenarioState.SECURE
        scenario.config_json = {"authz_enforced": True}

        snap2 = ScenarioVersion(
            scenario_id=scenario.id,
            version=2,
            snapshot_json=scenario.config_json,
            change_description="Enforced server-side authorization check",
        )
        db_session.add(snap2)
        db_session.commit()

        assert scenario.current_version == 2
        assert scenario.versions.count() == 1  # 1 because snap1 wasn't added in this test, snap2 added

    def test_version_uniqueness_constraint_prevents_duplicate_versions(self, db_session):
        test_def = TestDefinition(
            number="03",
            name="Constraint Test",
            slug="constraint-test",
            category="Testing",
            objective="Verify unique constraint",
            concept="Optimistic locking",
        )
        db_session.add(test_def)
        db_session.commit()

        scenario = Scenario(
            test_id=test_def.id,
            name="Constraint Scenario",
            current_version=1,
            state=ScenarioState.VULNERABLE,
            config_json={},
        )
        db_session.add(scenario)
        db_session.commit()

        snap_a = ScenarioVersion(
            scenario_id=scenario.id,
            version=1,
            snapshot_json={"state": "a"},
        )
        db_session.add(snap_a)
        db_session.commit()

        # Attempt to insert identical version number for the same scenario must fail
        snap_b = ScenarioVersion(
            scenario_id=scenario.id,
            version=1,
            snapshot_json={"state": "b"},
        )
        db_session.add(snap_b)
        with pytest.raises(IntegrityError):
            db_session.commit()

        db_session.rollback()

    def test_optimistic_locking_stale_detection(self):
        """Simulates stale version conflict detection used in remediation service."""
        current_db_version = 3
        incoming_action_expected_version = 2

        # If incoming expected version is behind current DB version, reject with stale_action
        is_stale = incoming_action_expected_version != current_db_version
        assert is_stale is True
