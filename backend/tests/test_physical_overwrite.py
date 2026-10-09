"""Raw overwrite must never record a partial pass as a completed one.

Uses disposable files and in-memory fake devices injected through the
``_open`` hook only; no real disk is opened.
"""
from __future__ import annotations

import errno

import pytest

import app.routes.operations as operations_route
import app.sanitization.engine as engine_module
from app.devices.discovery import PhysicalDevice
from app.sanitization import physical
from app.sanitization.engine import REQUIRED_PHYSICAL_PHRASE
from app.sanitization.physical import PhysicalWipeError, overwrite_device_passes

MIB = 1024 * 1024


class FakeDisk:
    """Writable fake device. Counts bytes instead of storing them."""

    def __init__(self, size, fail_at=None, fail_errno=errno.EBADF, max_write=None,
                 zero_write_at=None, close_error=False):
        self.size = size
        self.fail_at = fail_at
        self.fail_errno = fail_errno
        self.max_write = max_write
        self.zero_write_at = zero_write_at
        self.close_error = close_error
        self.pos = 0
        self.opens = []

    def opener(self, path, mode="rb", buffering=-1):
        self.opens.append((mode, buffering))
        self.pos = 0
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.close_error:
            raise OSError(errno.EBADF, "Bad file descriptor")
        return False

    def write(self, buf):
        if self.fail_at is not None and self.pos >= self.fail_at:
            raise OSError(self.fail_errno, "write failed")
        if self.zero_write_at is not None and self.pos >= self.zero_write_at:
            return 0
        n = len(buf) if self.max_write is None else min(len(buf), self.max_write)
        if self.pos + n > self.size:
            raise OSError(errno.ENOSPC, "No space left on device")
        self.pos += n
        return n

    def fileno(self):
        raise OSError(errno.EBADF, "no descriptor")  # fsync unsupported: tolerated


def test_zero_pass_overwrites_every_byte_of_a_disposable_file(tmp_path):
    size = 3 * MIB + 4096
    f = tmp_path / "disk.bin"
    f.write_bytes(b"\xAA" * size)
    records = overwrite_device_passes(str(f), size, ["zero"])
    assert records == [{"pass": "zero", "bytes_written": size}]
    assert f.read_bytes() == bytes(size)


def test_three_pass_purge_writes_full_capacity_each_pass(tmp_path):
    size = 2 * MIB + 512
    f = tmp_path / "disk.bin"
    f.write_bytes(b"\xAA" * size)
    records = overwrite_device_passes(str(f), size, ["zero", "one", "random"])
    assert [r["bytes_written"] for r in records] == [size, size, size]
    data = f.read_bytes()
    assert len(data) == size and data != b"\xFF" * size and data != bytes(size)


def test_device_is_opened_unbuffered_for_writing():
    disk = FakeDisk(2 * MIB)
    overwrite_device_passes("x", 2 * MIB, ["zero"], _open=disk.opener)
    assert disk.opens == [("rb+", 0)]


def test_write_error_midway_fails_the_pass():
    disk = FakeDisk(10 * MIB, fail_at=2 * MIB)
    with pytest.raises(PhysicalWipeError, match=f"offset {2 * MIB}"):
        overwrite_device_passes("x", 10 * MIB, ["zero"], _open=disk.opener)


def test_write_error_in_the_last_percent_is_not_treated_as_done():
    """The old code accepted anything past 99% (about 316 MB on a 32 GB stick)."""
    cap = 200 * MIB
    disk = FakeDisk(cap, fail_at=cap - MIB)  # error at 99.5%
    with pytest.raises(PhysicalWipeError, match="Write failed"):
        overwrite_device_passes("x", cap, ["zero"], _open=disk.opener)


def test_error_closing_after_a_partial_write_is_not_swallowed():
    """The 3 MiB 'verified' Purge run: a write failed, then closing the handle
    raised OSError too, and the old outer handler recorded the partial pass."""
    disk = FakeDisk(32 * MIB, fail_at=MIB, close_error=True)
    with pytest.raises(PhysicalWipeError):
        overwrite_device_passes("x", 32 * MIB, ["zero", "one", "random"], _open=disk.opener)


def test_error_closing_after_a_complete_pass_still_fails():
    disk = FakeDisk(2 * MIB, close_error=True)
    with pytest.raises(PhysicalWipeError, match="I/O error during zero pass"):
        overwrite_device_passes("x", 2 * MIB, ["zero"], _open=disk.opener)


def test_device_accepting_no_data_fails_instead_of_ending_the_pass():
    disk = FakeDisk(8 * MIB, zero_write_at=MIB)
    with pytest.raises(PhysicalWipeError, match="accepted no data"):
        overwrite_device_passes("x", 8 * MIB, ["zero"], _open=disk.opener)


def test_short_writes_are_continued_until_the_full_capacity():
    disk = FakeDisk(3 * MIB, max_write=300_000)
    records = overwrite_device_passes("x", 3 * MIB, ["zero"], _open=disk.opener)
    assert records == [{"pass": "zero", "bytes_written": 3 * MIB}]


def test_failure_in_a_later_pass_fails_the_whole_wipe():
    class FailsOnSecondOpen(FakeDisk):
        def opener(self, path, mode="rb", buffering=-1):
            super().opener(path, mode, buffering)
            self.fail_at = MIB if len(self.opens) == 2 else None
            return self

    disk = FailsOnSecondOpen(4 * MIB)
    with pytest.raises(PhysicalWipeError, match="one pass"):
        overwrite_device_passes("x", 4 * MIB, ["zero", "one", "random"], _open=disk.opener)


def test_unknown_capacity_writes_until_the_device_ends():
    size = 3 * MIB + 8192
    disk = FakeDisk(size)
    records = overwrite_device_passes("x", None, ["zero"], _open=disk.opener)
    assert records == [{"pass": "zero", "bytes_written": size}]


def test_unknown_capacity_reaches_a_tail_that_is_not_4k_aligned():
    size = 3 * MIB + 4096 + 1024  # two trailing 512-byte sectors
    disk = FakeDisk(size)
    records = overwrite_device_passes("x", None, ["zero"], _open=disk.opener)
    assert records == [{"pass": "zero", "bytes_written": size}]


def test_unknown_capacity_still_fails_on_other_errors():
    disk = FakeDisk(8 * MIB, fail_at=MIB)
    with pytest.raises(PhysicalWipeError, match="Write failed"):
        overwrite_device_passes("x", None, ["zero"], _open=disk.opener)


@pytest.mark.parametrize("error, message", [
    (PermissionError(errno.EACCES, "denied"), "Permission denied opening"),
    (FileNotFoundError(errno.ENOENT, "missing"), "not found"),
    (OSError(errno.EBUSY, "busy"), "Failed to open device"),
])
def test_open_errors_fail_with_a_clear_message(error, message):
    def opener(*args, **kwargs):
        raise error

    with pytest.raises(PhysicalWipeError, match=message):
        overwrite_device_passes("x", MIB, ["zero"], _open=opener)


def test_unknown_pass_kind_is_rejected():
    with pytest.raises(PhysicalWipeError, match="Unknown overwrite pass"):
        overwrite_device_passes("x", MIB, ["shred"], _open=FakeDisk(MIB).opener)


# --------------------------------------------------------------------------
# Through the API: a failed pass gives a failed operation and a Failed certificate
# --------------------------------------------------------------------------

def test_partial_physical_wipe_is_failed_never_verified(client, auth_headers, monkeypatch):
    cap = 8 * MIB
    device = PhysicalDevice(device_id="/dev/fake7", name="Fake USB", capacity_bytes=cap,
                            interface="USB", media_type="Removable", is_system_disk=False,
                            is_mounted=False)
    monkeypatch.setattr(operations_route, "discover_physical_devices", lambda: [device])
    monkeypatch.setattr(engine_module, "discover_physical_devices", lambda: [device])
    monkeypatch.setattr(engine_module, "_online_disk_windows", lambda idx: [])
    monkeypatch.setattr(engine_module, "get_device_length", lambda d, r=None: cap)
    disk = FakeDisk(cap, fail_at=MIB, close_error=True)
    real_overwrite = physical.overwrite_device_passes
    monkeypatch.setattr(engine_module, "overwrite_device_passes",
                        lambda device_id, capacity_bytes, passes:
                        real_overwrite(device_id, capacity_bytes, passes, _open=disk.opener))

    def no_verification(*args, **kwargs):
        raise AssertionError("verification must not run after a failed overwrite")

    monkeypatch.setattr(engine_module, "verify_device_zeroed", no_verification)
    monkeypatch.setattr(engine_module, "verify_device_full_readback", no_verification)

    r = client.post("/api/operations", json={
        "target_type": "physical", "target_identifier": "/dev/fake7",
        "method": "purge-three-pass-overwrite", "acknowledge_irrecoverable": True,
        "confirm_phrase": REQUIRED_PHYSICAL_PHRASE,
    }, headers=auth_headers)
    body = r.json()
    assert r.status_code == 201
    assert body["status"] == "failed"
    assert body["verification_status"] == "not_run"
    assert "overwrite_passes" not in body["evidence"]

    cert = client.post(f"/api/certificates/for-operation/{body['id']}", headers=auth_headers)
    assert cert.status_code == 201
    assert cert.json()["final_status"] == "Failed"
