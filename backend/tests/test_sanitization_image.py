from __future__ import annotations

from app.devices import images as image_lib
from app.models import Operation
from app.sanitization.engine import run_operation
from app.utils.hashing import new_id


def _make_image_operation(db_session, identifier: str, method: str) -> Operation:
    operation = Operation(
        id=new_id("OP"),
        target_type="image",
        target_identifier=identifier,
        target_label=f"Image: {identifier}",
        capacity_bytes=2 * 1024 * 1024,
        media_type="disk-image",
        method=method,
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
    return operation


def test_image_sanitization_succeeds_and_verifies(db_session, sample_image):
    original = image_lib.resolve_image(sample_image)
    operation = _make_image_operation(db_session, sample_image, "clear-single-pass-zero")

    result = run_operation(db_session, operation)

    assert result.status == "completed"
    assert result.verification_status == "verified"
    assert result.evidence["markers_found_before"] == 5
    assert result.evidence["markers_found_after"] == 0
    assert result.evidence["hash_changed"] is True
    assert result.evidence["original_untouched"] is True

    # Original image on disk must be byte-for-byte untouched.
    reresolved = image_lib.resolve_image(sample_image)
    assert reresolved.sha256 == original.sha256


def test_image_sanitization_cleans_up_working_copy(db_session, sample_image):
    from app.config import settings

    operation = _make_image_operation(db_session, sample_image, "clear-single-pass-zero")
    run_operation(db_session, operation)

    leftover = list(settings.workspace_dir.glob(f"{operation.id}__*"))
    assert leftover == []


def test_misapplied_method_is_reported_as_failed_not_success(db_session, sample_image):
    """A method with no overwrite passes (destroy-document-only) run against an
    image must not be reported as a successful sanitization -- markers survive,
    so the engine must honestly report FAILED verification."""
    operation = _make_image_operation(db_session, sample_image, "destroy-document-only")
    result = run_operation(db_session, operation)

    assert result.status == "completed"  # the command ran without crashing...
    assert result.verification_status == "failed"  # ...but did not sanitize anything
    assert result.evidence["markers_found_after"] > 0
