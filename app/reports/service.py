"""
app/reports/service.py — PDF and JSON report generation engine.

Produces audit-ready, sanitized technical and executive reports:
- Executive Summary
- Technical Findings & Classification (Severity, Confidence, Verification Status)
- Detailed Sanitized Evidence Records with Provenance Tags
- Remediation Guidance & Reproduction/Verification Procedures
- Strict exclusion of secrets, passwords, and sensitive session tokens
"""

from __future__ import annotations

import io
import json
import os
from datetime import datetime, timezone
from flask import current_app

from app.extensions import db
from app.models.execution import ExecutionRun
from app.models.report import ReportExport, ReportFormat


class ReportGeneratorService:
    @staticmethod
    def build_report_data(run: ExecutionRun) -> dict:
        """Construct sanitized structured report dictionary."""
        test_def = run.test_definition
        findings = run.findings.all()
        evidence = run.evidence_records.all()
        events = run.events.all()

        findings_data = []
        for f in findings:
            findings_data.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "verification_status": f.verification_status.value,
                "description": f.description,
                "verification_steps": f.verification_steps or [],
                "remediation_summary": f.remediation_summary,
            })

        evidence_data = []
        for e in evidence:
            evidence_data.append({
                "id": e.id,
                "title": e.title,
                "evidence_type": e.evidence_type.value,
                "provenance": e.provenance.value,
                "is_simulated": e.is_simulated,
                "observation": e.observation,
                "sanitized_detail": e.sanitized_detail,
                "collected_at": e.collected_at.isoformat() if e.collected_at else None,
            })

        events_data = []
        for ev in events:
            events_data.append({
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "event_type": ev.event_type,
                "detail": ev.detail,
            })

        has_simulated = any(e["is_simulated"] for e in evidence_data)

        report = {
            "metadata": {
                "report_title": f"Security Assessment: {test_def.name}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "Interactive Cybersecurity Lab v1.0",
                "tagline": "Learn. Test. Verify. Secure.",
                "policy_note": "No numeric overall security score computed. Evidence-driven verification.",
            },
            "execution": {
                "run_id": run.id,
                "test_id": test_def.number,
                "test_name": test_def.name,
                "category": test_def.category,
                "state": run.state.value,
                "scenario_version": run.scenario_version_at_run,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                "has_simulated_evidence": has_simulated,
            },
            "executive_summary": {
                "objective": test_def.objective,
                "concept": test_def.concept,
                "total_findings": len(findings_data),
                "total_evidence_collected": len(evidence_data),
                "status_summary": (
                    f"Test executed in {run.state.value} state. "
                    f"{'Findings detected requiring remediation.' if findings_data else 'No vulnerabilities identified in active configuration.'}"
                ),
            },
            "findings": findings_data,
            "evidence": evidence_data,
            "audit_trail": events_data,
        }
        return report

    @classmethod
    def generate_json_report(cls, run: ExecutionRun) -> str:
        """Returns pretty-printed sanitized JSON report."""
        data = cls.build_report_data(run)
        return json.dumps(data, indent=2)

    @classmethod
    def generate_pdf_report(cls, run: ExecutionRun) -> bytes:
        """Generates a styled, publication-ready PDF report via ReportLab."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        data = cls.build_report_data(run)
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0a0e1a"),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#555555"),
            spaceAfter=15,
        )
        h2_style = ParagraphStyle(
            "Heading2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#006699"),
            spaceBefore=14,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#222222"),
        )
        code_style = ParagraphStyle(
            "CodeBlock",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#111111"),
        )

        story = []

        # ── Header ─────────────────────────────────────────────────────────────
        story.append(Paragraph("Interactive Cybersecurity Lab", title_style))
        story.append(Paragraph("Security Assessment & Verification Report · <i>Learn. Test. Verify. Secure.</i>", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#006699"), spaceAfter=15))

        # ── Executive Summary Table ───────────────────────────────────────────
        meta_table_data = [
            [Paragraph("<b>Target Check:</b>", body_style), Paragraph(f"Test {data['execution']['test_id']}: {data['execution']['test_name']}", body_style)],
            [Paragraph("<b>Category:</b>", body_style), Paragraph(data['execution']['category'], body_style)],
            [Paragraph("<b>Execution State:</b>", body_style), Paragraph(data['execution']['state'].capitalize(), body_style)],
            [Paragraph("<b>Run ID:</b>", body_style), Paragraph(f"#{data['execution']['run_id']} (Scenario v{data['execution']['scenario_version']})", body_style)],
            [Paragraph("<b>Generated:</b>", body_style), Paragraph(data['metadata']['generated_at'], body_style)],
            [Paragraph("<b>Simulation Status:</b>", body_style), Paragraph("[SIMULATED EVIDENCE PRESENT]" if data['execution']['has_simulated_evidence'] else "Controlled Lab / Live", body_style)],
        ]
        meta_table = Table(meta_table_data, colWidths=[1.8 * inch, 5.0 * inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f4f7f9")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 15))

        # ── Objective & Principle ─────────────────────────────────────────────
        story.append(Paragraph("Assessment Objective & Principle", h2_style))
        story.append(Paragraph(data["executive_summary"]["objective"], body_style))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>Principle:</b> {data['executive_summary']['concept']}", body_style))
        story.append(Spacer(1, 12))

        # ── Findings ──────────────────────────────────────────────────────────
        story.append(Paragraph(f"Identified Findings ({len(data['findings'])})", h2_style))
        if data["findings"]:
            for f in data["findings"]:
                finding_box_data = [
                    [Paragraph(f"<b>{f['title']}</b>", body_style), Paragraph(f"Severity: <b>{f['severity'].upper()}</b> | Status: <b>{f['verification_status'].upper()}</b>", body_style)],
                    [Paragraph(f['description'], body_style), ""],
                ]
                if f.get("remediation_summary"):
                    finding_box_data.append([Paragraph(f"<b>Remediation:</b> {f['remediation_summary']}", body_style), ""])

                ft = Table(finding_box_data, colWidths=[4.8 * inch, 2.0 * inch])
                ft.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fff8f8") if f['severity'] in ['critical', 'high'] else colors.HexColor("#f8f9fa")),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#ffcccc") if f['severity'] in ['critical', 'high'] else colors.HexColor("#dddddd")),
                    ('SPAN', (0, 1), (1, 1)),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ]))
                story.append(ft)
                story.append(Spacer(1, 8))
        else:
            story.append(Paragraph("🛡️ <b>Clean Scenario:</b> No security vulnerabilities detected during this execution.", body_style))
            story.append(Spacer(1, 10))

        # ── Evidence ──────────────────────────────────────────────────────────
        story.append(Paragraph(f"Captured Technical Evidence ({len(data['evidence'])})", h2_style))
        for ev in data["evidence"]:
            ev_title = f"{'[SIMULATED] ' if ev['is_simulated'] else ''}{ev['title']} ({ev['evidence_type']})"
            ev_detail_str = json.dumps(ev["sanitized_detail"], indent=2)
            story.append(Paragraph(f"<b>• {ev_title}</b> — Provenance: <i>{ev['provenance']}</i>", body_style))
            if ev.get("observation"):
                story.append(Paragraph(f"Observation: {ev['observation']}", body_style))
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<pre>{ev_detail_str}</pre>", code_style))
            story.append(Spacer(1, 8))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @classmethod
    def record_export(
        cls,
        user_id: int,
        run_id: int,
        report_format: ReportFormat,
        content: bytes | str,
        filename: str,
    ) -> ReportExport:
        """Persists the report file and records ReportExport audit entry."""
        out_dir = current_app.config["REPORT_OUTPUT_DIR"]
        os.makedirs(out_dir, exist_ok=True)

        file_path = os.path.join(out_dir, filename)
        if isinstance(content, str):
            content = content.encode("utf-8")

        with open(file_path, "wb") as f:
            f.write(content)

        export_record = ReportExport(
            user_id=user_id,
            run_id=run_id,
            format=report_format,
            file_ref=filename,
            file_size_bytes=len(content),
        )
        db.session.add(export_record)
        db.session.commit()
        return export_record
