"""Sanitization engine orchestrator.

Dispatches an Operation to the image-based or physical-device
execution path based on its target_type, and always runs the verification
engine afterward. Every path records evidence on the Operation row and
audit events; nothing here silently claims success.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.audit.ledger import append_event
from app.config import settings
from app.devices import images as image_lib
from app.devices.discovery import discover_physical_devices, is_known_device_id
from app.models import Operation
from app.sanitization.overwrite import overwrite_file_passes
from app.sanitization.physical import (
    PhysicalWipeError,
    _extract_disk_index,
    _online_disk_windows,
    overwrite_device_passes,
    unmount_device,
    get_device_length,
    verify_device_full_readback,
    verify_device_zeroed,
)
from app.sanitization.policy import get_method
from app.verification.verifier import verify_image_operation

REQUIRED_PHYSICAL_PHRASE = "I UNDERSTAND DATA WILL BECOME IRRECOVERABLE"


class OperationError(Exception):
    pass


def run_operation(db: Session, operation: Operation) -> Operation:
    operation.status = "running"
    operation.started_at = datetime.utcnow()
    db.commit()
    append_event(db, "sanitization_started", operation.id, {"method": operation.method})

    try:
        if operation.target_type == "image":
            _run_image(db, operation)
        elif operation.target_type == "physical":
            _run_physical(db, operation)
        else:
            raise OperationError(f"Unknown target type: {operation.target_type}")
    except Exception as exc:  # noqa: BLE001
        operation.status = "failed"
        operation.verification_status = "not_run"
        operation.completed_at = datetime.utcnow()
        operation.errors = [*operation.errors, str(exc)]
        db.commit()
        append_event(db, "sanitization_failed", operation.id, {"error": str(exc)})
        return operation

    operation.completed_at = datetime.utcnow()
    db.commit()
    append_event(
        db,
        "sanitization_completed",
        operation.id,
        {"status": operation.status, "verification_status": operation.verification_status},
    )
    return operation


def _run_image(db: Session, operation: Operation) -> None:
    method = get_method(operation.method)
    image = image_lib.resolve_image(operation.target_identifier)

    pre_hash = image.sha256
    markers = image.manifest.get("markers", [])
    markers_before = len(markers)

    working_copy = image_lib.make_working_copy(image, operation.id)
    append_event(
        db,
        "working_copy_created",
        operation.id,
        {"working_copy": str(working_copy), "original_sha256": image.sha256},
    )

    pass_records = overwrite_file_passes(working_copy, method.passes)

    result = verify_image_operation(
        working_copy_path=working_copy,
        pre_hash=pre_hash,
        markers=markers,
        markers_before=markers_before,
        original_image_path=image.path,
        original_sha256_at_discovery=image.sha256,
    )

    operation.simulation_only = False
    operation.status = "completed"
    operation.verification_status = result.status
    operation.evidence = {
        **operation.evidence,
        "mode": "image-based",
        "image_identifier": image.identifier,
        "working_copy": str(working_copy),
        "overwrite_passes": pass_records,
        **result.to_dict(),
    }
    operation.warnings = [*operation.warnings, *result.warnings]
    operation.limitations = [*operation.limitations, *result.limitations]
    db.commit()

    append_event(
        db,
        "verification_performed",
        operation.id,
        {"verification_status": result.status, "original_untouched": result.original_untouched},
    )

    # Working copy was only ever a disposable test artifact.
    try:
        working_copy.unlink(missing_ok=True)
    except OSError:
        pass


def _run_physical(db: Session, operation: Operation) -> None:
    """Production physical-device sanitization path.

    Performs actual destructive overwrite on a real block device:
    1. Validates the device exists and is not the system disk
    2. Auto-unmounts if the device is currently mounted
    3. Opens the raw device and overwrites using the selected method passes
    4. Verifies by sampling the device content
    5. Brings the disk back online for re-use

    Requires elevated privileges (Administrator / root).
    """
    import platform as _platform

    device_id = operation.target_identifier
    method = get_method(operation.method)

    if not is_known_device_id(device_id):
        raise OperationError("Rejected: device identifier failed basic validation.")

    devices = {d.device_id: d for d in discover_physical_devices()}
    device = devices.get(device_id)
    if device is None:
        raise OperationError(
            "Rejected: device not found in current discovery results. "
            "Re-run discovery before attempting an operation."
        )
    if device.is_system_disk:
        raise OperationError(
            "Rejected: target is the system/OS disk. Physical sanitization of the "
            "disk hosting the running OS or this application is never permitted."
        )

    confirm_phrase = operation.evidence.get("confirm_phrase")
    if confirm_phrase != REQUIRED_PHYSICAL_PHRASE:
        raise OperationError("Rejected: required irrecoverable-data confirmation phrase missing/incorrect.")

    disk_index = _extract_disk_index(device_id)
    unmount_warnings: list[str] = []

    # --- Auto-unmount if mounted ---
    if device.is_mounted and device.mount_points:
        append_event(
            db, "device_unmount_started", operation.id,
            {"device_id": device_id, "mount_points": device.mount_points},
        )
        unmount_warnings = unmount_device(device_id, device.mount_points, disk_index)
        if unmount_warnings:
            operation.warnings = [*operation.warnings, *unmount_warnings]
        append_event(
            db, "device_unmount_completed", operation.id,
            {"warnings": unmount_warnings},
        )
        db.commit()

    # --- Handle destroy-document-only (no overwrite passes) ---
    if not method.passes:
        operation.simulation_only = False
        operation.status = "completed"
        operation.verification_status = "not_run"
        operation.evidence = {
            **operation.evidence,
            "mode": "physical-attestation",
            "device": device.to_dict(),
            "reason": (
                "Destroy method selected: no overwrite passes performed. "
                "This records an operator attestation that physical destruction "
                "was carried out through an external process."
            ),
        }
        operation.limitations = [
            *operation.limitations,
            method.limitations,
        ]
        # Bring disk back online if on Windows
        if _platform.system() == "Windows":
            _online_disk_windows(disk_index)
        return

    # --- Size the work from the device itself, not the OS-reported figure ---
    reported_capacity = device.capacity_bytes
    measured_capacity = get_device_length(device_id, reported_capacity)
    io_capacity = measured_capacity or reported_capacity
    if measured_capacity and reported_capacity and measured_capacity != reported_capacity:
        operation.warnings = [
            *operation.warnings,
            f"OS-reported capacity ({reported_capacity} bytes) differs from the measured device length "
            f"({measured_capacity} bytes); the measured length was used for the overwrite and verification.",
        ]
    elif not measured_capacity:
        operation.warnings = [
            *operation.warnings,
            "Could not measure the device length; the OS-reported capacity was used and the "
            "tail of the device may not be covered.",
        ]

    # --- Perform the actual overwrite ---
    append_event(
        db, "physical_overwrite_started", operation.id,
        {"device_id": device_id, "method": method.key, "passes": method.passes},
    )

    try:
        pass_records = overwrite_device_passes(
            device_id=device_id,
            capacity_bytes=io_capacity,
            passes=method.passes,
        )
    except PhysicalWipeError as exc:
        # Bring disk back online before raising
        if _platform.system() == "Windows":
            _online_disk_warnings = _online_disk_windows(disk_index)
            if _online_disk_warnings:
                operation.warnings = [*operation.warnings, *_online_disk_warnings]
        raise OperationError(str(exc))

    total_written = sum(p.get("bytes_written", 0) for p in pass_records)

    append_event(
        db, "physical_overwrite_completed", operation.id,
        {"passes": len(pass_records), "total_bytes_written": total_written},
    )

    # --- Verify (read-only): sampled by default, full read-back if the operator chose it ---
    final_pass = method.passes[-1]
    requested_mode = operation.evidence.get("requested_verification_mode", "sampled")
    verify_args = (device_id, io_capacity)
    if requested_mode == "full_readback" and final_pass == "zero":
        verify_result = verify_device_full_readback(*verify_args, expect_zero=True)
    else:
        verify_result = verify_device_zeroed(*verify_args, expect_zero=(final_pass == "zero"))
    verify_result["operation_id"] = operation.id

    # Determine verification status. An incomplete read is never "verified".
    if verify_result["status"] == "inconclusive" or total_written == 0:
        verification_status = "inconclusive"
        operation.warnings = [
            *operation.warnings,
            "Post-wipe verification incomplete: "
            f"{verify_result.get('verification_error', 'no data was written')}",
        ]
    elif final_pass == "zero":
        verification_status = verify_result["status"]  # verified | failed (non-zero data found)
    elif final_pass == "one" and verify_result.get("non_zero_bytes_found", 0) == 0:
        verification_status = "inconclusive"
    else:
        # Random/one-fill: non-zero is expected; only readability and writes are confirmed.
        verification_status = "verified"

    # Bring disk back online
    online_warnings: list[str] = []
    if _platform.system() == "Windows":
        online_warnings = _online_disk_windows(disk_index)
        if online_warnings:
            operation.warnings = [*operation.warnings, *online_warnings]

    operation.simulation_only = False
    operation.status = "completed"
    operation.verification_status = verification_status
    operation.evidence = {
        **operation.evidence,
        "mode": "physical-destructive",
        "device": device.to_dict(),
        "overwrite_passes": pass_records,
        "total_bytes_written": total_written,
        "reported_capacity_bytes": reported_capacity,
        "measured_capacity_bytes": measured_capacity,
        "verification": verify_result,
        "unmount_warnings": unmount_warnings,
    }
    operation.limitations = [
        *operation.limitations,
        method.limitations,
    ]

    append_event(
        db, "verification_performed", operation.id,
        {"verification_status": verification_status, "verification": verify_result},
    )
