from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    app_name: str
    app_version: str


class PhysicalDeviceOut(BaseModel):
    device_id: str
    name: str
    capacity_bytes: int | None
    interface: str | None
    media_type: str | None
    is_system_disk: bool
    is_mounted: bool
    mount_points: list[str]
    partitions: list[dict]


class ImageTargetOut(BaseModel):
    identifier: str
    target_type: str
    size_bytes: int
    marker_count: int
    media_type_label: str
    description: str


class DevicesResponse(BaseModel):
    physical_devices: list[PhysicalDeviceOut]
    image_targets: list[ImageTargetOut]
    discovery_warnings: list[str] = Field(default_factory=list)


class MethodOut(BaseModel):
    key: str
    label: str
    policy_level: str
    policy_reference: str
    limitations: str
    supports_full_readback: bool = False


class OperationCreate(BaseModel):
    target_type: Literal["image", "physical"]
    target_identifier: str = Field(default="", max_length=512)
    method: str
    capacity_bytes: int | None = Field(default=None, ge=1, le=1024 * 1024 * 1024)
    # Required only for target_type == "physical"
    confirm_phrase: str | None = None
    acknowledge_irrecoverable: bool = False
    # Physical zero-overwrite only. "sampled" (default, fast) or "full_readback" (reads every byte).
    verification_mode: Literal["sampled", "full_readback"] = "sampled"


class OperationOut(BaseModel):
    id: str
    target_type: str
    target_identifier: str
    target_label: str
    capacity_bytes: int | None
    media_type: str | None
    method: str
    policy_level: str
    policy_reference: str
    status: str
    verification_status: str
    simulation_only: bool
    operator_id: str
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    evidence: dict[str, Any]
    errors: list[Any]
    warnings: list[Any]
    limitations: list[Any]

    model_config = {"from_attributes": True}


class CertificateOut(BaseModel):
    id: str
    operation_id: str
    final_status: str
    content_hash: str
    signature_algorithm: str
    public_key_fingerprint: str | None
    issued_at: datetime

    model_config = {"from_attributes": True}


class CertificateVerifyOut(BaseModel):
    valid: bool
    hash_matches: bool | None = None
    signature_valid: bool | None = None
    fingerprint_matches: bool | None = None
    recomputed_hash: str | None = None
    stored_hash: str | None = None
    reason: str | None = None


class AuditEventOut(BaseModel):
    seq: int
    operation_id: str | None
    event_type: str
    timestamp: datetime
    evidence: dict[str, Any]
    prev_hash: str
    entry_hash: str

    model_config = {"from_attributes": True}


class AuditChainStatus(BaseModel):
    intact: bool
    total_events: int
    first_invalid_seq: int | None
    limitation: str
