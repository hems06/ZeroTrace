"""Verification of physical devices: sampled and full read-back.

All tests use in-memory fake devices injected through the verifier's `_open`
hook (or disposable files / monkeypatched engine functions). Nothing here
touches a real device and nothing opens a device for writing.
"""
from __future__ import annotations

import pytest

import app.routes.operations as operations_route
import app.sanitization.engine as engine_module
from app.devices.discovery import PhysicalDevice
from app.sanitization.engine import REQUIRED_PHYSICAL_PHRASE
from app.sanitization.physical import (
    estimate_full_readback_seconds,
    verify_device_full_readback,
    verify_device_zeroed,
)

MIB = 1024 * 1024


class FakeDevice:
    """Read-only in-memory 'device'. Records modes and read sizes it was given."""

    def __init__(self, data: bytes, max_read: int | None = None, fail_at: int | None = None):
        self.data = data
        self.max_read = max_read  # cap bytes returned per read() -> short reads
        self.fail_at = fail_at  # raise OSError once position >= fail_at
        self.pos = 0
        self.modes: list[str] = []
        self.read_sizes: list[int] = []

    def opener(self, path, mode="rb", buffering=-1):
        self.modes.append(mode)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def seek(self, pos, whence=0):
        self.pos = pos
        return pos

    def read(self, n):
        self.read_sizes.append(n)
        if self.fail_at is not None and self.pos >= self.fail_at:
            raise OSError(5, "Input/output error")
        if self.max_read:
            n = min(n, self.max_read)
        out = self.data[self.pos : self.pos + n]
        self.pos += len(out)
        return out


# --------------------------------------------------------------------------
# Sampled mode
# --------------------------------------------------------------------------

def test_sampled_zero_device_is_verified_with_structured_record():
    size = 64 * MIB
    dev = FakeDevice(bytes(size))
    rec = verify_device_zeroed("x", size, _open=dev.opener)
    assert rec["method"] == "sampled"
    assert rec["status"] == "verified" and rec["read_complete"] is True
    assert rec["device_capacity_bytes"] == size
    assert rec["samples_checked"] == len(rec["sample_offsets"]) >= 16
    assert rec["bytes_checked"] == rec["samples_checked"] * rec["sample_size_bytes"]
    assert rec["sample_offsets"][0] == 0
    assert rec["non_zero_bytes_found"] == 0
    assert "evidence, not proof" in rec["limitations"]
    assert rec["started_at"] and rec["completed_at"]
    assert dev.modes == ["rb"]


def test_sampled_detects_nonzero_data_in_tail_sample():
    size = 64 * MIB
    data = bytearray(size)
    data[size - 512 : size - 506] = b"SECRET"
    rec = verify_device_zeroed("x", size, _open=FakeDevice(bytes(data)).opener)
    assert rec["status"] == "failed"
    assert rec["non_zero_bytes_found"] == 6


def test_sampled_nonzero_between_samples_is_not_seen_and_says_so():
    """Sampling cannot see everything -- the record must not claim otherwise."""
    size = 64 * MIB
    data = bytearray(size)
    # Land in a gap: past the head sample, before the second sample offset.
    probe = verify_device_zeroed("x", size, _open=FakeDevice(bytes(size)).opener)
    gap = probe["sample_offsets"][0] + probe["sample_size_bytes"] + 4096
    assert gap < probe["sample_offsets"][1]
    data[gap] = 1
    rec = verify_device_zeroed("x", size, _open=FakeDevice(bytes(data)).opener)
    assert rec["status"] == "verified" and rec["method"] == "sampled"
    assert rec["bytes_checked"] < size
    assert "NOT examined" in rec["limitations"]


@pytest.mark.parametrize("capacity", [None, 0, -5])
def test_sampled_unknown_capacity_is_inconclusive(capacity):
    rec = verify_device_zeroed("x", capacity, _open=FakeDevice(bytes(8192)).opener)
    assert rec["status"] == "inconclusive"
    assert "capacity" in rec["verification_error"]


def test_sampled_capacity_larger_than_device_is_inconclusive():
    """Reported capacity is bigger than what the device returns -> short read."""
    dev = FakeDevice(bytes(8 * MIB))
    rec = verify_device_zeroed("x", 64 * MIB, _open=dev.opener)
    assert rec["status"] == "inconclusive"
    assert rec["read_complete"] is False
    assert "Incomplete read" in rec["verification_error"]


def test_sampled_read_error_partway_is_inconclusive():
    size = 64 * MIB
    rec = verify_device_zeroed("x", size, _open=FakeDevice(bytes(size), fail_at=size // 2).opener)
    assert rec["status"] == "inconclusive"
    assert rec["read_errors"] and "Input/output error" in rec["read_errors"][0]["error"]
    assert rec["samples_checked"] < len(rec["sample_offsets"])


def test_sampled_open_failure_is_inconclusive():
    def boom(*a, **k):
        raise PermissionError(13, "denied")

    rec = verify_device_zeroed("x", 8 * MIB, _open=boom)
    assert rec["status"] == "inconclusive" and rec["read_errors"]


def test_sampled_short_reads_that_complete_are_counted_but_verified():
    size = 16 * MIB
    dev = FakeDevice(bytes(size), max_read=256 * 1024)
    rec = verify_device_zeroed("x", size, _open=dev.opener)
    assert rec["status"] == "verified"
    assert rec["short_reads"] > 0


def test_sampled_non_zero_pattern_only_confirms_readability():
    size = 16 * MIB
    rec = verify_device_zeroed("x", size, expect_zero=False, _open=FakeDevice(b"\xff" * size).opener)
    assert rec["status"] == "verified"
    assert rec["expected_pattern"] == "not_checked"
    assert any("only readability" in w for w in rec["warnings"])


# --------------------------------------------------------------------------
# Full read-back mode
# --------------------------------------------------------------------------

def test_full_readback_zero_device_is_verified():
    size = 10 * MIB
    dev = FakeDevice(bytes(size))
    rec = verify_device_full_readback("x", size, chunk_size=MIB, _open=dev.opener)
    assert rec["method"] == "full_readback"
    assert rec["status"] == "verified" and rec["read_complete"] is True
    assert rec["bytes_checked"] == size == rec["device_capacity_bytes"]
    assert rec["non_zero_bytes_found"] == 0
    assert "sample_offsets" not in rec
    assert "every addressable byte" in rec["limitations"]
    assert "flash cells" in rec["limitations"]
    assert dev.modes == ["rb"]  # opened read-only


def test_full_readback_is_bounded_to_chunk_size():
    size = 10 * MIB
    dev = FakeDevice(bytes(size))
    verify_device_full_readback("x", size, chunk_size=MIB, _open=dev.opener)
    assert max(dev.read_sizes) <= MIB


def test_full_readback_unaligned_size_handles_final_partial_chunk():
    size = 5 * MIB + 1234  # not a multiple of the chunk or of a sector
    dev = FakeDevice(bytes(size))
    rec = verify_device_full_readback("x", size, chunk_size=MIB, _open=dev.opener)
    assert rec["status"] == "verified"
    assert rec["bytes_checked"] == size


def test_full_readback_detects_nonzero_in_final_partial_chunk():
    size = 5 * MIB + 1234
    data = bytearray(size)
    data[-3:] = b"abc"
    rec = verify_device_full_readback("x", size, chunk_size=MIB, _open=FakeDevice(bytes(data)).opener)
    assert rec["status"] == "failed"
    assert rec["non_zero_bytes_found"] == 3
    assert rec["bytes_checked"] == size


def test_full_readback_catches_data_a_sampled_check_misses():
    size = 64 * MIB
    data = bytearray(size)
    probe = verify_device_zeroed("x", size, _open=FakeDevice(bytes(size)).opener)
    data[probe["sample_offsets"][0] + probe["sample_size_bytes"] + 4096] = 1
    dev = bytes(data)
    assert verify_device_zeroed("x", size, _open=FakeDevice(dev).opener)["status"] == "verified"
    assert verify_device_full_readback("x", size, _open=FakeDevice(dev).opener)["status"] == "failed"


def test_full_readback_read_error_partway_is_inconclusive():
    size = 10 * MIB
    dev = FakeDevice(bytes(size), fail_at=4 * MIB)
    rec = verify_device_full_readback("x", size, chunk_size=MIB, _open=dev.opener)
    assert rec["status"] == "inconclusive" and rec["read_complete"] is False
    assert rec["bytes_checked"] == 4 * MIB
    assert rec["read_errors"][0]["offset"] == 4 * MIB
    assert "Input/output error" in rec["verification_error"]


def test_full_readback_read_error_never_masks_nonzero_data():
    size = 10 * MIB
    data = bytearray(size)
    data[100] = 9
    rec = verify_device_full_readback("x", size, chunk_size=MIB, _open=FakeDevice(bytes(data), fail_at=5 * MIB).opener)
    assert rec["status"] == "inconclusive"  # incomplete read never reports verified or failed
    assert rec["non_zero_bytes_found"] == 1


def test_full_readback_device_smaller_than_reported_capacity_is_inconclusive():
    dev = FakeDevice(bytes(6 * MIB))
    rec = verify_device_full_readback("x", 10 * MIB, chunk_size=MIB, _open=dev.opener)
    assert rec["status"] == "inconclusive"
    assert rec["bytes_checked"] == 6 * MIB
    assert "capacity inconsistent" in rec["verification_error"]


def test_full_readback_device_larger_than_reported_capacity_is_inconclusive():
    dev = FakeDevice(bytes(12 * MIB))
    rec = verify_device_full_readback("x", 10 * MIB, chunk_size=MIB, _open=dev.opener)
    assert rec["status"] == "inconclusive"
    assert rec["bytes_checked"] == 10 * MIB
    assert "beyond its reported capacity" in rec["verification_error"]


def test_full_readback_read_past_end_raising_oserror_is_fine():
    class StrictEnd(FakeDevice):
        def read(self, n):
            if self.pos >= len(self.data):
                raise OSError(22, "Invalid argument")
            return super().read(n)

    size = 4 * MIB
    rec = verify_device_full_readback("x", size, chunk_size=MIB, _open=StrictEnd(bytes(size)).opener)
    assert rec["status"] == "verified"


def test_full_readback_short_reads_are_retried_and_counted():
    size = 4 * MIB
    dev = FakeDevice(bytes(size), max_read=300_000)
    rec = verify_device_full_readback("x", size, chunk_size=MIB, _open=dev.opener)
    assert rec["status"] == "verified"
    assert rec["bytes_checked"] == size
    assert rec["short_reads"] > 0


def test_full_readback_stalled_device_returning_nothing_is_inconclusive():
    class Stalls(FakeDevice):
        def read(self, n):
            return b"" if self.pos >= 2 * MIB else super().read(n)

    rec = verify_device_full_readback("x", 4 * MIB, chunk_size=MIB, _open=Stalls(bytes(4 * MIB)).opener)
    assert rec["status"] == "inconclusive"
    assert rec["bytes_checked"] == 2 * MIB


@pytest.mark.parametrize("capacity", [None, 0, -1])
def test_full_readback_unknown_capacity_is_inconclusive(capacity):
    rec = verify_device_full_readback("x", capacity, _open=FakeDevice(bytes(4096)).opener)
    assert rec["status"] == "inconclusive"
    assert rec["bytes_checked"] == 0


def test_full_readback_works_on_a_real_disposable_file(tmp_path):
    f = tmp_path / "disk.bin"
    f.write_bytes(bytes(3 * MIB + 17))
    ok = verify_device_full_readback(str(f), f.stat().st_size, chunk_size=MIB)
    assert ok["status"] == "verified"
    with open(f, "r+b") as fh:
        fh.seek(2 * MIB)
        fh.write(b"\x01")
    bad = verify_device_full_readback(str(f), f.stat().st_size, chunk_size=MIB)
    assert bad["status"] == "failed" and bad["non_zero_bytes_found"] == 1


def test_estimate_scales_with_capacity():
    assert estimate_full_readback_seconds(None) is None
    small, big = estimate_full_readback_seconds(MIB * 100), estimate_full_readback_seconds(MIB * 1000)
    assert 0 < small < big


# --------------------------------------------------------------------------
# Engine / API integration (overwrite and OS calls mocked: no device is written)
# --------------------------------------------------------------------------

CAP = 8 * 1024 * MIB


def _device() -> PhysicalDevice:
    return PhysicalDevice(
        device_id="/dev/fake9",
        name="Fake USB",
        capacity_bytes=CAP,
        interface="USB",
        media_type="Removable",
        is_system_disk=False,
        is_mounted=False,
    )


@pytest.fixture()
def physical_env(monkeypatch):
    devices = [_device()]
    monkeypatch.setattr(operations_route, "discover_physical_devices", lambda: devices)
    monkeypatch.setattr(engine_module, "discover_physical_devices", lambda: devices)
    monkeypatch.setattr(engine_module, "_online_disk_windows", lambda idx: [])
    calls = {"overwrite": 0, "sampled": 0, "full": 0}

    def fake_overwrite(device_id, capacity_bytes, passes):
        calls["overwrite"] += 1
        return [{"pass": p, "bytes_written": capacity_bytes} for p in passes]

    monkeypatch.setattr(engine_module, "overwrite_device_passes", fake_overwrite)
    return calls


def _rec(method, status, **extra):
    base = {
        "method": method,
        "status": status,
        "read_complete": status != "inconclusive",
        "device_capacity_bytes": CAP,
        "bytes_checked": CAP if method == "full_readback" else 16 * MIB,
        "non_zero_bytes_found": 0,
        "short_reads": 0,
        "read_errors": [],
        "warnings": [],
        "started_at": "t0",
        "completed_at": "t1",
        "limitations": "lim",
    }
    base.update(extra)
    return base


def _post(client, headers, **over):
    body = {
        "target_type": "physical",
        "target_identifier": "/dev/fake9",
        "method": "clear-single-pass-zero",
        "acknowledge_irrecoverable": True,
        "confirm_phrase": REQUIRED_PHYSICAL_PHRASE,
    }
    body.update(over)
    return client.post("/api/operations", json=body, headers=headers)


def test_default_is_sampled_and_records_structured_evidence(client, auth_headers, monkeypatch, physical_env):
    seen = {}

    def sampled(device_id, cap, **kw):
        seen["sampled"] = (cap, kw)
        return _rec("sampled", "verified")

    def full(*a, **k):
        raise AssertionError("full read-back must not run unless requested")

    monkeypatch.setattr(engine_module, "verify_device_zeroed", sampled)
    monkeypatch.setattr(engine_module, "verify_device_full_readback", full)
    body = _post(client, auth_headers).json()
    assert body["status"] == "completed" and body["verification_status"] == "verified"
    v = body["evidence"]["verification"]
    assert v["method"] == "sampled" and v["operation_id"] == body["id"]
    assert seen["sampled"][0] == CAP
    assert body["evidence"]["requested_verification_mode"] == "sampled"


def test_full_readback_requested_runs_full_verifier(client, auth_headers, monkeypatch, physical_env):
    monkeypatch.setattr(engine_module, "verify_device_zeroed", lambda *a, **k: pytest.fail("sampled ran"))
    monkeypatch.setattr(engine_module, "verify_device_full_readback", lambda *a, **k: _rec("full_readback", "verified"))
    body = _post(client, auth_headers, verification_mode="full_readback").json()
    assert body["verification_status"] == "verified"
    assert body["evidence"]["verification"]["method"] == "full_readback"
    assert body["evidence"]["verification"]["bytes_checked"] == CAP


def test_full_readback_nonzero_data_marks_operation_failed(client, auth_headers, monkeypatch, physical_env):
    monkeypatch.setattr(
        engine_module, "verify_device_full_readback",
        lambda *a, **k: _rec("full_readback", "failed", non_zero_bytes_found=42),
    )
    body = _post(client, auth_headers, verification_mode="full_readback").json()
    assert body["verification_status"] == "failed"


@pytest.mark.parametrize("mode,fn", [("sampled", "verify_device_zeroed"), ("full_readback", "verify_device_full_readback")])
def test_incomplete_verification_is_inconclusive_with_warning(client, auth_headers, monkeypatch, physical_env, mode, fn):
    monkeypatch.setattr(
        engine_module, fn,
        lambda *a, **k: _rec(mode, "inconclusive", verification_error="Input/output error"),
    )
    body = _post(client, auth_headers, verification_mode=mode).json()
    assert body["status"] == "completed"
    assert body["verification_status"] == "inconclusive"
    assert any("Input/output error" in w for w in body["warnings"])


def test_full_readback_rejected_for_non_zero_final_pass(client, auth_headers, physical_env):
    r = _post(client, auth_headers, method="purge-three-pass-overwrite", verification_mode="full_readback")
    assert r.status_code == 400
    assert physical_env["overwrite"] == 0  # rejected before anything ran


def test_full_readback_rejected_for_image_targets(client, auth_headers, sample_image):
    r = client.post(
        "/api/operations",
        json={
            "target_type": "image",
            "target_identifier": sample_image,
            "method": "clear-single-pass-zero",
            "verification_mode": "full_readback",
        },
        headers=auth_headers,
    )
    assert r.status_code == 400


def test_invalid_verification_mode_rejected(client, auth_headers, physical_env):
    assert _post(client, auth_headers, verification_mode="everything").status_code == 422


def test_certificate_shows_method_and_limitations(client, auth_headers, monkeypatch, physical_env):
    monkeypatch.setattr(
        engine_module, "verify_device_zeroed",
        lambda *a, **k: _rec(
            "sampled", "verified", sample_offsets=[0, 4096], sample_size_bytes=4096, samples_checked=2,
            limitations="Sampled verification: only the listed windows were read back.",
        ),
    )
    op = _post(client, auth_headers).json()
    cert = client.post(f"/api/certificates/for-operation/{op['id']}", headers=auth_headers)
    assert cert.status_code == 201
    assert cert.json()["final_status"] == "Verified"
    pdf = client.get(f"/api/certificates/{cert.json()['id']}/download")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_verification_estimate_endpoint(client):
    r = client.get("/api/verification/estimate", params={"capacity_bytes": 31659102720})
    assert r.status_code == 200
    assert r.json()["full_readback_seconds"] > 600


# --------------------------------------------------------------------------
# True device length (OS-reported size can be smaller than the disk)
# --------------------------------------------------------------------------

def test_probe_length_finds_true_end_beyond_reported_size():
    from app.sanitization.physical import _probe_length

    true_len = 20 * MIB + 3 * 4096
    dev = FakeDevice(bytes(true_len))

    class Strict(FakeDevice):
        def read(self, n):
            if self.pos + n > len(self.data):
                raise OSError(22, "Invalid argument")
            return super().read(n)

    strict = Strict(bytes(true_len))
    assert _probe_length("x", 16 * MIB, _open=strict.opener) == true_len
    assert _probe_length("x", 16 * MIB, _open=dev.opener) == true_len  # EOF-style device too
    assert strict.modes and set(strict.modes) == {"rb"}


def test_probe_length_unreadable_start_returns_none():
    from app.sanitization.physical import _probe_length

    assert _probe_length("x", 8 * MIB, _open=FakeDevice(bytes(MIB)).opener) is None


def test_engine_sizes_overwrite_and_verification_from_measured_length(client, auth_headers, monkeypatch, physical_env):
    measured = CAP + 8 * MIB
    seen = {}

    def fake_overwrite(device_id, capacity_bytes, passes):
        seen["overwrite_cap"] = capacity_bytes
        return [{"pass": p, "bytes_written": capacity_bytes} for p in passes]

    def fake_verify(device_id, cap, **kw):
        seen["verify_cap"] = cap
        return _rec("sampled", "verified", device_capacity_bytes=cap)

    monkeypatch.setattr(engine_module, "get_device_length", lambda d, r=None: measured)
    monkeypatch.setattr(engine_module, "overwrite_device_passes", fake_overwrite)
    monkeypatch.setattr(engine_module, "verify_device_zeroed", fake_verify)
    body = _post(client, auth_headers).json()
    assert seen == {"overwrite_cap": measured, "verify_cap": measured}
    assert body["evidence"]["reported_capacity_bytes"] == CAP
    assert body["evidence"]["measured_capacity_bytes"] == measured
    assert body["evidence"]["total_bytes_written"] == measured
    assert any("differs from the measured device length" in w for w in body["warnings"])


def test_engine_warns_when_length_cannot_be_measured(client, auth_headers, monkeypatch, physical_env):
    monkeypatch.setattr(engine_module, "get_device_length", lambda d, r=None: None)
    monkeypatch.setattr(engine_module, "verify_device_zeroed", lambda *a, **k: _rec("sampled", "verified"))
    body = _post(client, auth_headers).json()
    assert body["evidence"]["measured_capacity_bytes"] is None
    assert any("Could not measure the device length" in w for w in body["warnings"])
