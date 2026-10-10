from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit.ledger import append_event
from app.database import SessionLocal, get_db
from app.devices import images as image_lib
from app.devices.discovery import discover_physical_devices
from app.models import Operation
from app.sanitization.engine import REQUIRED_PHYSICAL_PHRASE, run_operation
from app.sanitization.policy import get_method
from app.schemas import OperationCreate, OperationOut
from app.security import require_operator
from app.utils.hashing import new_id

router = APIRouter(prefix="/api/operations", tags=["operations"])


def _execute_operation_async(operation_id: str) -> None:
    """Run the sanitization on a background thread with its own DB session.

    The wipe can take a while (seconds to many minutes), so the HTTP request
    returns immediately with a 'pending' operation and clients poll
    GET /api/operations/{id} to watch status + progress and estimate the time
    remaining.
    """
    session = SessionLocal()
    try:
        operation = session.get(Operation, operation_id)
        if operation is not None:
            run_operation(session, operation)
    finally:
        session.close()


@router.get("", response_model=list[OperationOut])
def list_operations(db: Session = Depends(get_db)) -> list[OperationOut]:
    ops = db.query(Operation).order_by(Operation.created_at.desc()).all()
    return [OperationOut.model_validate(o) for o in ops]


@router.get("/{operation_id}", response_model=OperationOut)
def get_operation(operation_id: str, db: Session = Depends(get_db)) -> OperationOut:
    op = db.get(Operation, operation_id)
    if op is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Operation not found.")
    return OperationOut.model_validate(op)


@router.post("", response_model=OperationOut, status_code=status.HTTP_201_CREATED)
def create_operation(
    payload: OperationCreate,
    db: Session = Depends(get_db),
    operator_id: str = Depends(require_operator),
) -> OperationOut:
    try:
        method = get_method(payload.method)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    if payload.verification_mode == "full_readback":
        if payload.target_type != "physical":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Full read-back verification applies to physical devices only.")
        if not method.passes or method.passes[-1] != "zero":
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Full read-back verification is only supported for methods whose final pass is a zero overwrite.",
            )

    operation_id = new_id("OP")

    if payload.target_type == "image":
        try:
            image = image_lib.resolve_image(payload.target_identifier)
        except image_lib.InvalidImageReference as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        append_event(db, "target_discovered", None, {"image": image.identifier, "sha256": image.sha256})
        target_identifier = image.identifier
        target_label = f"Image: {image.identifier}"
        capacity_bytes = image.size_bytes
        media_type = image.manifest.get("media_type_label", "disk-image")
        evidence_seed = {}

    elif payload.target_type == "physical":
        if not payload.target_identifier:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "target_identifier (device id) is required.")
        if not payload.acknowledge_irrecoverable or payload.confirm_phrase != REQUIRED_PHYSICAL_PHRASE:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Physical operations require acknowledge_irrecoverable=true and "
                f"confirm_phrase == '{REQUIRED_PHYSICAL_PHRASE}'.",
            )
        devices = {d.device_id: d for d in discover_physical_devices()}
        device = devices.get(payload.target_identifier)
        if device is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Device not found in current discovery results; re-run discovery first.",
            )
        append_event(db, "target_discovered", None, {"device": device.to_dict()})
        target_identifier = device.device_id
        target_label = device.name
        capacity_bytes = device.capacity_bytes
        media_type = device.media_type
        evidence_seed = {"confirm_phrase": payload.confirm_phrase, "requested_verification_mode": payload.verification_mode}

    else:  # pragma: no cover - constrained by Literal in schema
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unsupported target_type.")

    operation = Operation(
        id=operation_id,
        target_type=payload.target_type,
        target_identifier=target_identifier,
        target_label=target_label,
        capacity_bytes=capacity_bytes,
        media_type=media_type,
        method=method.key,
        policy_level=method.policy_level,
        policy_reference=method.policy_reference,
        status="pending",
        verification_status="not_run",
        simulation_only=False,
        operator_id=operator_id,
        evidence=evidence_seed,
        errors=[],
        warnings=[],
        limitations=[],
    )
    db.add(operation)
    db.commit()

    append_event(db, "target_selected", operation.id, {"target_type": payload.target_type, "target_identifier": target_identifier})
    append_event(db, "operator_confirmation_completed", operation.id, {"operator_id": operator_id})

    # Execute asynchronously so the wipe's progress can be polled while it runs.
    threading.Thread(target=_execute_operation_async, args=(operation.id,), daemon=True).start()
    return OperationOut.model_validate(operation)


@router.post("/{operation_id}/verify", response_model=OperationOut)
def reverify_operation(
    operation_id: str,
    db: Session = Depends(get_db),
    operator_id: str = Depends(require_operator),
) -> OperationOut:
    """Re-check that the recorded verification_status is internally consistent
    with the stored evidence. Working copies/synthetic datasets are disposable
    and deleted after each run by design, so re-verification works from the
    recorded evidence rather than re-reading deleted files."""
    operation = db.get(Operation, operation_id)
    if operation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Operation not found.")
    if operation.status not in ("completed", "failed"):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Operation is '{operation.status}', not yet finished.")

    evidence = operation.evidence
    markers_after = evidence.get("markers_found_after")
    hash_changed = evidence.get("hash_changed")
    original_untouched = evidence.get("original_untouched", True)

    consistent = True
    if markers_after is not None and hash_changed is not None:
        if operation.verification_status == "verified" and not (markers_after == 0 and hash_changed and original_untouched):
            consistent = False
        if operation.verification_status == "failed" and (markers_after == 0 and hash_changed and original_untouched):
            consistent = False

    append_event(
        db,
        "verification_performed",
        operation.id,
        {"recheck": True, "consistent_with_stored_evidence": consistent, "operator_id": operator_id},
    )
    if not consistent:
        operation.warnings = [*operation.warnings, "Re-verification found stored evidence inconsistent with recorded status."]
        operation.verification_status = "inconclusive"
        db.commit()

    return OperationOut.model_validate(operation)
