"""
app/presets/service.py — Preset management, schema validation, and import pipeline.

Enforces:
- Schema validation and version compatibility
- Conflict detection (duplicate names / external IDs)
- Transaction-safe atomic import with rollback on failure
- Sensitive data exclusion during export
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.extensions import db
from app.models.preset import Preset


class PresetSchemaError(ValueError):
    """Raised when an imported preset schema is invalid or unsupported."""


class PresetService:
    SUPPORTED_SCHEMA_VERSIONS = {1}

    @classmethod
    def export_preset_json(cls, preset: Preset) -> dict[str, Any]:
        """Produce an exportable, portable JSON package excluding private state."""
        return {
            "schema_version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "preset": {
                "name": preset.name,
                "description": preset.description,
                "version": preset.version,
                "config_json": preset.config_json,
                "external_id": preset.external_id or f"preset_{preset.id}_{preset.name.lower().replace(' ', '_')}",
            },
        }

    @classmethod
    def validate_import_data(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Validates the structure and schema of an import payload."""
        if not isinstance(data, dict):
            raise PresetSchemaError("Import payload must be a JSON object.")

        schema_version = data.get("schema_version")
        if schema_version not in cls.SUPPORTED_SCHEMA_VERSIONS:
            raise PresetSchemaError(
                f"Unsupported schema version: {schema_version}. "
                f"Supported versions: {list(cls.SUPPORTED_SCHEMA_VERSIONS)}"
            )

        preset_data = data.get("preset")
        if not isinstance(preset_data, dict):
            raise PresetSchemaError("Payload missing 'preset' definition dictionary.")

        name = preset_data.get("name")
        if not name or not isinstance(name, str) or not name.strip():
            raise PresetSchemaError("Preset 'name' must be a non-empty string.")

        config = preset_data.get("config_json")
        if config is None or not isinstance(config, dict):
            raise PresetSchemaError("Preset 'config_json' must be a valid dictionary.")

        return preset_data

    @classmethod
    def preview_import(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Inspect proposed import and identify collisions before persisting."""
        preset_data = cls.validate_import_data(data)
        name = preset_data["name"].strip()
        external_id = preset_data.get("external_id")

        existing_by_name = Preset.query.filter_by(name=name).first()
        existing_by_ext = (
            Preset.query.filter_by(external_id=external_id).first()
            if external_id
            else None
        )

        collision = existing_by_name or existing_by_ext
        return {
            "name": name,
            "description": preset_data.get("description", ""),
            "version": preset_data.get("version", 1),
            "config_json": preset_data["config_json"],
            "has_collision": collision is not None,
            "collision_id": collision.id if collision else None,
            "collision_name": collision.name if collision else None,
        }

    @classmethod
    def execute_import(
        cls,
        data: dict[str, Any],
        user_id: int,
        resolution_mode: str = "create_new",  # "create_new" | "replace" | "skip"
    ) -> tuple[Preset | None, str]:
        """
        Applies import transactionally.
        Returns (Preset instance, status message).
        Rolls back on any error.
        """
        preset_data = cls.validate_import_data(data)
        name = preset_data["name"].strip()
        description = preset_data.get("description", "")
        config_json = preset_data["config_json"]
        version = preset_data.get("version", 1)
        external_id = preset_data.get("external_id")

        existing = Preset.query.filter(
            (Preset.name == name) | (Preset.external_id == external_id)
        ).first()

        try:
            if existing:
                if resolution_mode == "skip":
                    return existing, f"Preset '{name}' skipped (already exists)."
                elif resolution_mode == "replace":
                    existing.description = description
                    existing.config_json = config_json
                    existing.version = max(existing.version + 1, version)
                    existing.is_active = True
                    db.session.commit()
                    return existing, f"Preset '{name}' replaced successfully."
                elif resolution_mode == "create_new":
                    # Rename to avoid unique constraint collision
                    new_name = f"{name} (Imported {datetime.now(timezone.utc).strftime('%H%M%S')})"
                    preset = Preset(
                        name=new_name,
                        description=description,
                        version=1,
                        created_by_id=user_id,
                        config_json=config_json,
                        external_id=None,
                        is_active=True,
                    )
                    db.session.add(preset)
                    db.session.commit()
                    return preset, f"Imported as new preset '{new_name}'."
                else:
                    raise PresetSchemaError(f"Unknown resolution mode: {resolution_mode}")
            else:
                preset = Preset(
                    name=name,
                    description=description,
                    version=version,
                    created_by_id=user_id,
                    config_json=config_json,
                    external_id=external_id,
                    is_active=True,
                )
                db.session.add(preset)
                db.session.commit()
                return preset, f"Preset '{name}' created successfully."

        except Exception as e:
            db.session.rollback()
            raise PresetSchemaError(f"Import transaction failed: {e}") from e
