"""
tests/unit/test_preset_schema.py — Unit tests for preset schema validation and import resolution.
"""

import pytest

from app.models.preset import Preset
from app.presets.service import PresetSchemaError, PresetService


def test_validate_valid_payload():
    valid = {
        "schema_version": 1,
        "preset": {
            "name": "Strict Verification Preset",
            "description": "Enforces strict CSP headers.",
            "version": 1,
            "config_json": {"strict": True},
        },
    }
    preset_data = PresetService.validate_import_data(valid)
    assert preset_data["name"] == "Strict Verification Preset"
    assert preset_data["config_json"] == {"strict": True}


def test_validate_invalid_schema_version():
    invalid = {
        "schema_version": 999,
        "preset": {"name": "Test", "config_json": {}},
    }
    with pytest.raises(PresetSchemaError, match="Unsupported schema version"):
        PresetService.validate_import_data(invalid)


def test_validate_missing_name():
    invalid = {
        "schema_version": 1,
        "preset": {"description": "No name", "config_json": {}},
    }
    with pytest.raises(PresetSchemaError, match="Preset 'name' must be a non-empty string"):
        PresetService.validate_import_data(invalid)


def test_execute_import_create_and_replace(db_session, admin_user):
    payload = {
        "schema_version": 1,
        "preset": {
            "name": "Custom Test Preset",
            "description": "Initial version",
            "version": 1,
            "config_json": {"mode": "initial"},
            "external_id": "test_preset_ext_01",
        },
    }

    # 1. Initial import
    preset, msg = PresetService.execute_import(payload, admin_user.id, "create_new")
    assert preset is not None
    assert preset.name == "Custom Test Preset"
    assert "created successfully" in msg

    # 2. Replace import on collision
    payload["preset"]["description"] = "Updated version"
    payload["preset"]["config_json"] = {"mode": "updated"}
    updated, rep_msg = PresetService.execute_import(payload, admin_user.id, "replace")
    assert updated.id == preset.id
    assert updated.description == "Updated version"
    assert "replaced successfully" in rep_msg

    # 3. Skip import on collision
    _, skip_msg = PresetService.execute_import(payload, admin_user.id, "skip")
    assert "skipped" in skip_msg
