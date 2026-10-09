"""Certificate-of-sanitization generation.

Certificates are built entirely from recorded Operation data -- never from
assumptions about what "should" have happened. The signed payload is a
canonical JSON document (not the PDF bytes), so verification is robust to
PDF re-rendering and is checked independently of the static file.
"""
from __future__ import annotations

import json
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from sqlalchemy.orm import Session

from app.certificates.signing import public_key_fingerprint, sign_bytes, verify_signature
from app.config import settings
from app.models import Certificate, Operation
from app.utils.hashing import new_id, sha256_bytes

APP_NAME = settings.app_name
APP_VERSION = settings.app_version


def determine_final_status(operation: Operation) -> str:
    if operation.status in ("blocked_safety_disabled", "blocked_not_implemented", "failed"):
        return "Failed"
    if operation.verification_status == "verified":
        return "Simulation Only" if operation.simulation_only else "Verified"
    if operation.verification_status == "inconclusive":
        return "Inconclusive"
    if operation.verification_status == "failed":
        return "Failed"
    return "Inconclusive"


def _canonical_payload(operation: Operation, certificate_id: str, final_status: str, issued_at: datetime) -> dict:
    return {
        "certificate_id": certificate_id,
        "operation_id": operation.id,
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "target_type": operation.target_type,
        "target_identifier": operation.target_identifier,
        "target_label": operation.target_label,
        "capacity_bytes": operation.capacity_bytes,
        "media_type": operation.media_type,
        "method": operation.method,
        "policy_level": operation.policy_level,
        "policy_reference": operation.policy_reference,
        "started_at": operation.started_at.isoformat() if operation.started_at else None,
        "completed_at": operation.completed_at.isoformat() if operation.completed_at else None,
        "operator_id": operation.operator_id,
        "evidence": operation.evidence,
        "errors": operation.errors,
        "warnings": operation.warnings,
        "limitations": operation.limitations,
        "final_status": final_status,
        "simulation_only": operation.simulation_only,
        "issued_at": issued_at.isoformat(),
    }


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _build_pdf(path, payload: dict, signature_b64: str, content_hash: str, fingerprint: str) -> None:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TETitle", parent=styles["Title"], textColor=colors.HexColor("#0b3d59"))
    h2 = ParagraphStyle("TEH2", parent=styles["Heading2"], textColor=colors.HexColor("#0b3d59"))
    normal = styles["Normal"]
    mono = ParagraphStyle("Mono", parent=styles["Code"], fontSize=7.5, leading=9)

    doc = SimpleDocTemplate(str(path), pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    flow = []

    flow.append(Paragraph(f"{APP_NAME} — Certificate of Sanitization", title_style))
    flow.append(Paragraph("Secure Data Wiping for Trustworthy IT Asset Recycling", normal))
    flow.append(Spacer(1, 10))

    status_hex = {
        "Verified": "#1b7f3d",
        "Simulation Only": "#8a6d00",
        "Failed": "#b31212",
        "Inconclusive": "#b31212",
    }.get(payload["final_status"], "#000000")
    flow.append(
        Paragraph(
            f'<b>Final status: <font color="{status_hex}">{payload["final_status"]}</font></b>',
            ParagraphStyle("Status", parent=styles["Heading1"], fontSize=16),
        )
    )
    if payload["final_status"] == "Simulation Only":
        flow.append(
            Paragraph(
                "This certificate documents a DEMONSTRATION-MODE operation on synthetic "
                "test data in an isolated workspace. No physical storage device was wiped.",
                normal,
            )
        )
    flow.append(Spacer(1, 8))

    def kv_table(rows):
        t = Table(rows, colWidths=[55 * mm, 120 * mm])
        t.setStyle(
            TableStyle(
                [
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#444444")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return t

    flow.append(Paragraph("Identifiers", h2))
    flow.append(
        kv_table(
            [
                ["Certificate ID", payload["certificate_id"]],
                ["Operation ID", payload["operation_id"]],
                ["Target type", payload["target_type"]],
                ["Target identifier", payload["target_identifier"]],
                ["Target label", payload["target_label"]],
                ["Capacity (bytes)", str(payload["capacity_bytes"])],
                ["Media type", str(payload["media_type"])],
            ]
        )
    )
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("Sanitization", h2))
    flow.append(
        kv_table(
            [
                ["Method", payload["method"]],
                ["Policy level", payload["policy_level"]],
                ["Policy reference", payload["policy_reference"]],
                ["Started at (UTC)", str(payload["started_at"])],
                ["Completed at (UTC)", str(payload["completed_at"])],
                ["Operator", payload["operator_id"]],
                ["Simulation only", str(payload["simulation_only"])],
            ]
        )
    )
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("Verification evidence", h2))
    evidence_rows = [[k, str(v)[:400]] for k, v in payload["evidence"].items()]
    if evidence_rows:
        flow.append(kv_table(evidence_rows))
    else:
        flow.append(Paragraph("No evidence recorded.", normal))
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("Warnings", h2))
    flow.append(Paragraph("<br/>".join(payload["warnings"]) or "None", normal))
    flow.append(Spacer(1, 8))
    flow.append(Paragraph("Scope and limitations", h2))
    flow.append(Paragraph("<br/>".join(payload["limitations"]) or "None recorded.", normal))
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("Certificate integrity", h2))
    flow.append(
        kv_table(
            [
                ["App version", payload["app_version"]],
                ["Issued at (UTC)", payload["issued_at"]],
                ["Content hash (SHA-256)", content_hash],
                ["Signature algorithm", "RSA-3072 PSS / SHA-256"],
                ["Public key fingerprint", fingerprint],
            ]
        )
    )
    flow.append(Spacer(1, 4))
    flow.append(Paragraph("Digital signature (base64):", normal))
    flow.append(Paragraph(signature_b64, mono))
    flow.append(Spacer(1, 10))
    flow.append(
        Paragraph(
            "Verify this certificate's authenticity and integrity via "
            "POST /api/certificates/{id}/verify, which recomputes the content hash from "
            "stored operation data and checks the signature against the server's public key.",
            normal,
        )
    )

    doc.build(flow)


def create_certificate(db: Session, operation: Operation) -> Certificate:
    certificate_id = new_id("CERT")
    issued_at = datetime.utcnow()
    final_status = determine_final_status(operation)

    payload = _canonical_payload(operation, certificate_id, final_status, issued_at)
    canonical = _canonical_bytes(payload)
    content_hash = sha256_bytes(canonical)
    signature_b64 = sign_bytes(canonical)
    fingerprint = public_key_fingerprint()

    pdf_path = settings.certificates_dir / f"{certificate_id}.pdf"
    _build_pdf(pdf_path, payload, signature_b64, content_hash, fingerprint)

    cert = Certificate(
        id=certificate_id,
        operation_id=operation.id,
        final_status=final_status,
        pdf_path=str(pdf_path),
        content_hash=content_hash,
        signature_b64=signature_b64,
        public_key_fingerprint=fingerprint,
        signature_algorithm="RSA-3072-PSS-SHA256",
        issued_at=issued_at,
    )
    db.add(cert)
    db.commit()
    db.refresh(cert)
    return cert


def verify_certificate(db: Session, certificate: Certificate) -> dict:
    operation = db.get(Operation, certificate.operation_id)
    if operation is None:
        return {"valid": False, "reason": "Referenced operation no longer exists."}

    payload = _canonical_payload(operation, certificate.id, certificate.final_status, certificate.issued_at)
    canonical = _canonical_bytes(payload)
    recomputed_hash = sha256_bytes(canonical)

    hash_matches = recomputed_hash == certificate.content_hash
    signature_valid = verify_signature(canonical, certificate.signature_b64 or "")
    current_fingerprint = public_key_fingerprint()
    fingerprint_matches = current_fingerprint == certificate.public_key_fingerprint

    return {
        "valid": hash_matches and signature_valid and fingerprint_matches,
        "hash_matches": hash_matches,
        "signature_valid": signature_valid,
        "fingerprint_matches": fingerprint_matches,
        "recomputed_hash": recomputed_hash,
        "stored_hash": certificate.content_hash,
    }
