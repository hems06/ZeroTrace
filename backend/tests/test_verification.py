from __future__ import annotations

from app.devices import images as image_lib
import app.verification.verifier as verifier_module
from app.verification.verifier import verify_image_operation


def test_verify_detects_successful_sanitization(tmp_path, sample_image):
    image = image_lib.resolve_image(sample_image)
    working_copy = image_lib.make_working_copy(image, "OP-VERIFYOK")
    with open(working_copy, "r+b") as f:
        f.write(b"\x00" * working_copy.stat().st_size)

    result = verify_image_operation(
        working_copy_path=working_copy,
        pre_hash=image.sha256,
        markers=image.manifest["markers"],
        markers_before=len(image.manifest["markers"]),
        original_image_path=image.path,
        original_sha256_at_discovery=image.sha256,
    )
    assert result.status == "verified"
    assert result.markers_found_after == 0
    working_copy.unlink()


def test_verify_detects_failed_sanitization_when_markers_survive(sample_image):
    image = image_lib.resolve_image(sample_image)
    working_copy = image_lib.make_working_copy(image, "OP-VERIFYFAIL")
    # No overwrite at all -- markers still present.

    result = verify_image_operation(
        working_copy_path=working_copy,
        pre_hash=image.sha256,
        markers=image.manifest["markers"],
        markers_before=len(image.manifest["markers"]),
        original_image_path=image.path,
        original_sha256_at_discovery=image.sha256,
    )
    assert result.status == "failed"
    assert result.markers_found_after > 0
    assert any("still detected" in w for w in result.warnings)
    working_copy.unlink()


def test_verify_is_inconclusive_when_scan_exceeds_scan_cap(monkeypatch, sample_image):
    monkeypatch.setattr(verifier_module, "MAX_FULL_SCAN_BYTES", 0)
    image = image_lib.resolve_image(sample_image)
    working_copy = image_lib.make_working_copy(image, "OP-VERIFYINC")
    with open(working_copy, "r+b") as f:
        f.write(b"\x00" * working_copy.stat().st_size)

    result = verify_image_operation(
        working_copy_path=working_copy,
        pre_hash=image.sha256,
        markers=image.manifest["markers"],
        markers_before=len(image.manifest["markers"]),
        original_image_path=image.path,
        original_sha256_at_discovery=image.sha256,
    )
    assert result.status == "inconclusive"
    assert any("too large" in w for w in result.warnings)
    working_copy.unlink()


def test_verify_flags_original_tampering_as_failed(tmp_path, sample_image):
    image = image_lib.resolve_image(sample_image)
    working_copy = image_lib.make_working_copy(image, "OP-VERIFYTAMPER")
    with open(working_copy, "r+b") as f:
        f.write(b"\x00" * working_copy.stat().st_size)

    # Simulate the original having been mutated after discovery (should
    # never happen in the real flow, but the verifier must catch it).
    result = verify_image_operation(
        working_copy_path=working_copy,
        pre_hash=image.sha256,
        markers=image.manifest["markers"],
        markers_before=len(image.manifest["markers"]),
        original_image_path=image.path,
        original_sha256_at_discovery="0" * 64,  # wrong hash on purpose
    )
    assert result.status == "failed"
    assert result.original_untouched is False
    working_copy.unlink()
