from __future__ import annotations

from app.certificates.generator import create_certificate, verify_certificate
from app.devices import images as image_lib
from app.models import Operation
from app.sanitization.engine import run_operation
from app.utils.hashing import new_id


def _completed_image_operation(db_session, sample_image) -> Operation:
    operation = Operation(
        id=new_id("OP"),
        target_type="image",
        target_identifier=sample_image,
        target_label=f"Image: {sample_image}",
        capacity_bytes=2 * 1024 * 1024,
        media_type="demo-disk-image",
        method="clear-single-pass-zero",
        policy_level="clear",
        policy_reference="test",
        status="pending",
        verification_status="not_run",
        simulation_only=False,
        operator_id="test-operator",
        evidence={},
        errors=[],
        warnings=[],
        limitations=[],
    )
    db_session.add(operation)
    db_session.commit()
    run_operation(db_session, operation)
    return operation


def test_certificate_generation_and_verification(db_session, sample_image):
    operation = _completed_image_operation(db_session, sample_image)
    cert = create_certificate(db_session, operation)

    assert cert.final_status == "Verified"
    assert cert.signature_b64
    from pathlib import Path

    assert Path(cert.pdf_path).exists()
    assert Path(cert.pdf_path).stat().st_size > 0

    result = verify_certificate(db_session, cert)
    assert result["valid"] is True
    assert result["hash_matches"] is True
    assert result["signature_valid"] is True


def test_certificate_verification_detects_tampered_hash(db_session, sample_image):
    operation = _completed_image_operation(db_session, sample_image)
    cert = create_certificate(db_session, operation)

    cert.content_hash = "0" * 64  # tamper
    db_session.commit()

    result = verify_certificate(db_session, cert)
    assert result["valid"] is False
    assert result["hash_matches"] is False


def test_certificate_verification_detects_tampered_signature(db_session, sample_image):
    operation = _completed_image_operation(db_session, sample_image)
    cert = create_certificate(db_session, operation)

    cert.signature_b64 = cert.signature_b64[:-4] + "AAAA"
    db_session.commit()

    result = verify_certificate(db_session, cert)
    assert result["valid"] is False
    assert result["signature_valid"] is False


def test_simulation_only_certificate_is_labeled_honestly(db_session):
    operation = Operation(
        id=new_id("OP"),
        target_type="demo",
        target_identifier="synthetic-demo-dataset",
        target_label="Synthetic demo dataset",
        capacity_bytes=1024 * 1024,
        media_type="demo-synthetic",
        method="clear-single-pass-zero",
        policy_level="clear",
        policy_reference="test",
        status="pending",
        verification_status="not_run",
        simulation_only=True,
        operator_id="test-operator",
        evidence={},
        errors=[],
        warnings=[],
        limitations=[],
    )
    db_session.add(operation)
    db_session.commit()
    run_operation(db_session, operation)

    cert = create_certificate(db_session, operation)
    assert cert.final_status == "Simulation Only"
