from __future__ import annotations

import app.routes.operations as operations_route
import app.sanitization.engine as engine_module
from app.devices.discovery import PhysicalDevice
from app.sanitization.engine import REQUIRED_PHYSICAL_PHRASE


def _patch_devices(monkeypatch, devices: list[PhysicalDevice]) -> None:
    monkeypatch.setattr(operations_route, "discover_physical_devices", lambda: devices)
    monkeypatch.setattr(engine_module, "discover_physical_devices", lambda: devices)


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_unauthorized_operation_creation_rejected(client):
    r = client.post("/api/operations", json={"target_type": "demo", "method": "clear-single-pass-zero"})
    assert r.status_code == 401

    r2 = client.post(
        "/api/operations",
        json={"target_type": "demo", "method": "clear-single-pass-zero"},
        headers={"X-Operator-Token": "wrong-token"},
    )
    assert r2.status_code == 403


def test_invalid_method_rejected(client, auth_headers):
    r = client.post(
        "/api/operations",
        json={"target_type": "demo", "method": "not-a-real-method"},
        headers=auth_headers,
    )
    assert r.status_code == 400


def test_invalid_target_type_rejected(client, auth_headers):
    r = client.post(
        "/api/operations",
        json={"target_type": "cloud", "method": "clear-single-pass-zero"},
        headers=auth_headers,
    )
    assert r.status_code == 422  # fails Literal validation


def test_image_path_traversal_rejected_via_api(client, auth_headers):
    r = client.post(
        "/api/operations",
        json={"target_type": "image", "target_identifier": "../secret.img", "method": "clear-single-pass-zero"},
        headers=auth_headers,
    )
    assert r.status_code == 400


def test_image_not_found_rejected_via_api(client, auth_headers):
    r = client.post(
        "/api/operations",
        json={"target_type": "image", "target_identifier": "nope.img", "method": "clear-single-pass-zero"},
        headers=auth_headers,
    )
    assert r.status_code == 400


def test_demo_operation_end_to_end_via_api(client, auth_headers):
    r = client.post(
        "/api/operations",
        json={"target_type": "demo", "method": "clear-single-pass-zero"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "completed"
    assert body["simulation_only"] is True

    cert_r = client.post(f"/api/certificates/for-operation/{body['id']}", headers=auth_headers)
    assert cert_r.status_code == 201
    cert_id = cert_r.json()["id"]

    verify_r = client.post(f"/api/certificates/{cert_id}/verify")
    assert verify_r.json()["valid"] is True

    download_r = client.get(f"/api/certificates/{cert_id}/download")
    assert download_r.status_code == 200
    assert download_r.headers["content-type"] == "application/pdf"


def test_image_operation_end_to_end_via_api(client, auth_headers, sample_image):
    r = client.post(
        "/api/operations",
        json={"target_type": "image", "target_identifier": sample_image, "method": "clear-single-pass-zero"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "completed"
    assert body["verification_status"] == "verified"
    assert body["simulation_only"] is False


def test_physical_operation_requires_confirmation_phrase(client, auth_headers, monkeypatch):
    device = PhysicalDevice(
        device_id="/dev/fake0",
        name="Fake USB Drive",
        capacity_bytes=16 * 1024 * 1024 * 1024,
        interface="USB",
        media_type="Removable",
        is_system_disk=False,
        is_mounted=False,
    )
    _patch_devices(monkeypatch, [device])

    r = client.post(
        "/api/operations",
        json={
            "target_type": "physical",
            "target_identifier": "/dev/fake0",
            "method": "clear-single-pass-zero",
            "acknowledge_irrecoverable": False,
        },
        headers=auth_headers,
    )
    assert r.status_code == 400


def test_physical_operation_rejects_system_disk(client, auth_headers, monkeypatch):
    system_disk = PhysicalDevice(
        device_id="/dev/sda",
        name="System Disk",
        capacity_bytes=512 * 1024 * 1024 * 1024,
        interface="NVMe",
        media_type="SSD",
        is_system_disk=True,
        is_mounted=True,
    )
    _patch_devices(monkeypatch, [system_disk])

    r = client.post(
        "/api/operations",
        json={
            "target_type": "physical",
            "target_identifier": "/dev/sda",
            "method": "clear-single-pass-zero",
            "acknowledge_irrecoverable": True,
            "confirm_phrase": REQUIRED_PHYSICAL_PHRASE,
        },
        headers=auth_headers,
    )
    assert r.status_code == 201  # operation is recorded...
    body = r.json()
    assert body["status"] == "failed"  # ...but never executed
    assert "system/OS disk" in body["errors"][0]


def test_physical_operation_blocked_by_default_safety_flag(client, auth_headers, monkeypatch):
    removable = PhysicalDevice(
        device_id="/dev/fake1",
        name="Fake Removable Drive",
        capacity_bytes=8 * 1024 * 1024 * 1024,
        interface="USB",
        media_type="Removable",
        is_system_disk=False,
        is_mounted=False,
    )
    _patch_devices(monkeypatch, [removable])

    r = client.post(
        "/api/operations",
        json={
            "target_type": "physical",
            "target_identifier": "/dev/fake1",
            "method": "clear-single-pass-zero",
            "acknowledge_irrecoverable": True,
            "confirm_phrase": REQUIRED_PHYSICAL_PHRASE,
        },
        headers=auth_headers,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "blocked_safety_disabled"
    assert body["simulation_only"] is True


def test_interrupted_operation_reports_failure_not_false_success(client, auth_headers, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("simulated disk I/O interruption")

    monkeypatch.setattr(engine_module, "overwrite_file_passes", boom)

    r = client.post(
        "/api/operations",
        json={"target_type": "demo", "method": "clear-single-pass-zero"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "failed"
    assert "simulated disk I/O interruption" in body["errors"][0]
    assert body["verification_status"] == "not_run"


def test_audit_log_and_chain_endpoints(client, auth_headers):
    client.post("/api/operations", json={"target_type": "demo", "method": "clear-single-pass-zero"}, headers=auth_headers)
    events = client.get("/api/audit").json()
    assert len(events) > 0

    chain = client.get("/api/audit/verify-chain").json()
    assert chain["intact"] is True


def test_dashboard_summary_reflects_real_state(client, auth_headers):
    before = client.get("/api/dashboard/summary").json()["total_operations"]
    client.post("/api/operations", json={"target_type": "demo", "method": "clear-single-pass-zero"}, headers=auth_headers)
    after = client.get("/api/dashboard/summary").json()["total_operations"]
    assert after == before + 1


def test_reverify_endpoint_requires_finished_operation(client, auth_headers):
    r = client.post(
        "/api/operations",
        json={"target_type": "demo", "method": "clear-single-pass-zero"},
        headers=auth_headers,
    )
    op_id = r.json()["id"]
    verify_r = client.post(f"/api/operations/{op_id}/verify", headers=auth_headers)
    assert verify_r.status_code == 200

    missing_r = client.post("/api/operations/OP-doesnotexist/verify", headers=auth_headers)
    assert missing_r.status_code == 404
