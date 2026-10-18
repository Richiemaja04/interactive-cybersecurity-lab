"""
app/presets/routes.py — Preset management and import/export routes.
"""

from __future__ import annotations

import json
from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from app.auth.decorators import require_admin, require_tester
from app.extensions import db
from app.models.preset import Preset
from app.presets.service import PresetSchemaError, PresetService

presets_bp = Blueprint("presets", __name__)


@presets_bp.route("/")
@login_required
@require_tester
def index():
    """List approved scenario presets."""
    presets = Preset.query.filter_by(is_active=True).order_by(Preset.name).all()
    return render_template("presets/index.html", presets=presets)


@presets_bp.route("/new", methods=["POST"])
@login_required
@require_admin
def create_preset():
    """Create a new scenario preset (Admin only)."""
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    config_raw = request.form.get("config_json", "{}")

    if not name:
        flash("Preset name cannot be empty.", "error")
        return redirect(url_for("presets.index"))

    try:
        config_json = json.loads(config_raw)
        if not isinstance(config_json, dict):
            raise ValueError("Configuration must be a JSON object.")
    except Exception as e:
        flash(f"Invalid JSON configuration: {e}", "error")
        return redirect(url_for("presets.index"))

    existing = Preset.query.filter_by(name=name).first()
    if existing:
        flash(f"Preset named '{name}' already exists.", "error")
        return redirect(url_for("presets.index"))

    preset = Preset(
        name=name,
        description=description,
        version=1,
        created_by_id=current_user.id,
        config_json=config_json,
        is_active=True,
    )
    db.session.add(preset)
    db.session.commit()

    flash(f"Preset '{name}' successfully created.", "success")
    return redirect(url_for("presets.index"))


@presets_bp.route("/<int:preset_id>/export")
@login_required
@require_tester
def export_preset(preset_id: int):
    """Export a preset as an audit-safe JSON package."""
    preset = Preset.query.get_or_404(preset_id)
    export_dict = PresetService.export_preset_json(preset)
    json_bytes = json.dumps(export_dict, indent=2)

    filename = f"preset_{preset.id}_{preset.name.lower().replace(' ', '_')}.json"
    return Response(
        json_bytes,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@presets_bp.route("/import", methods=["POST"])
@login_required
@require_admin
def import_preset():
    """Import a preset JSON package with collision resolution (Admin only)."""
    import_file = request.files.get("preset_file")
    raw_json = request.form.get("preset_json")
    resolution_mode = request.form.get("resolution_mode", "create_new")

    try:
        if import_file and import_file.filename:
            payload = json.load(import_file)
        elif raw_json:
            payload = json.loads(raw_json)
        else:
            flash("No preset file or JSON content provided.", "error")
            return redirect(url_for("presets.index"))

        preset, msg = PresetService.execute_import(
            data=payload,
            user_id=current_user.id,
            resolution_mode=resolution_mode,
        )
        flash(msg, "success")
    except PresetSchemaError as pse:
        flash(f"Preset import rejected: {pse}", "error")
    except Exception as e:
        flash(f"Unexpected import error: {e}", "error")

    return redirect(url_for("presets.index"))
