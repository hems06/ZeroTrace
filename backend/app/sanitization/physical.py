"""Physical device sanitization primitives.

Handles platform-specific unmounting and raw block-device overwrite for
actual production wipes. This module performs DESTRUCTIVE, IRRECOVERABLE
writes to physical storage devices.

Requires elevated privileges (Administrator on Windows, root on Linux).
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

_CHUNK = 1024 * 1024  # 1 MiB write chunks


class PhysicalWipeError(Exception):
    pass


# ---------------------------------------------------------------------------
# Unmount helpers
# ---------------------------------------------------------------------------

def _unmount_windows(mount_points: list[str], disk_index: int | None) -> list[str]:
    """Forcefully take volumes offline on Windows via diskpart.

    Uses 'offline disk' which removes all mount points on the target disk
    so the raw device handle can be opened exclusively.
    """
    warnings: list[str] = []

    if disk_index is None:
        # Fallback: try to remove each drive letter individually
        for mp in mount_points:
            letter = mp.rstrip(":\\").upper()
            if not letter or len(letter) != 1:
                continue
            script = f"select volume {letter}\nremove letter={letter}\n"
            try:
                result = subprocess.run(
                    ["diskpart"],
                    input=script,
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode != 0:
                    warnings.append(f"diskpart remove letter={letter} returned {result.returncode}: {result.stderr.strip()[:200]}")
            except Exception as exc:
                warnings.append(f"Failed to remove drive letter {letter}: {exc}")
        return warnings

    # Preferred: keep the disk ONLINE and remove its volumes with 'clean'.
    # An offline disk (or one with mounted volumes) rejects raw writes: Windows
    # returns access denied, which the C runtime surfaces as EBADF.
    script = f"select disk {disk_index}\nattributes disk clear readonly\nonline disk\nclean\n"
    try:
        result = subprocess.run(
            ["diskpart"],
            input=script,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or "succeeded in cleaning" not in result.stdout.lower():
            warnings.append(f"diskpart clean disk {disk_index} failed ({result.returncode}): {(result.stdout + result.stderr).strip()[-300:]}")
    except Exception as exc:
        warnings.append(f"Failed to offline disk {disk_index}: {exc}")
    return warnings


def _unmount_linux(mount_points: list[str], device_id: str) -> list[str]:
    """Unmount all mount points for a device on Linux."""
    warnings: list[str] = []
    for mp in mount_points:
        try:
            result = subprocess.run(
                ["umount", "-f", mp],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                warnings.append(f"umount {mp} failed: {result.stderr.strip()[:200]}")
        except Exception as exc:
            warnings.append(f"Failed to unmount {mp}: {exc}")
    return warnings


def unmount_device(device_id: str, mount_points: list[str], disk_index: int | None = None) -> list[str]:
    """Unmount a device. Returns a list of warnings (empty = success)."""
    if not mount_points:
        return []

    system = platform.system()
    if system == "Windows":
        return _unmount_windows(mount_points, disk_index)
    elif system == "Linux":
        return _unmount_linux(mount_points, device_id)
    else:
        return [f"Auto-unmount not implemented for platform '{system}'. Unmount manually."]


# ---------------------------------------------------------------------------
# Bring disk back online (Windows) after wipe
# ---------------------------------------------------------------------------

def _online_disk_windows(disk_index: int | None) -> list[str]:
    """Bring a disk back online after wipe so the OS can re-detect it."""
    warnings: list[str] = []
    if disk_index is None:
        return warnings
    script = f"select disk {disk_index}\nonline disk\n"
    try:
        result = subprocess.run(
            ["diskpart"],
            input=script,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            warnings.append(f"diskpart online disk {disk_index} returned {result.returncode}")
    except Exception as exc:
        warnings.append(f"Failed to bring disk {disk_index} back online: {exc}")
    return warnings


# ---------------------------------------------------------------------------
# Raw device overwrite
# ---------------------------------------------------------------------------

def _extract_disk_index(device_id: str) -> int | None:
    """Extract disk index from Windows device ID like \\\\.\\PHYSICALDRIVE1."""
    import re
    m = re.search(r"PHYSICALDRIVE(\d+)", device_id, re.IGNORECASE)
    return int(m.group(1)) if m else None


def _windows_length_ioctl(device_id: str) -> int | None:
    """IOCTL_DISK_GET_LENGTH_INFO: the real addressable size of a raw disk. READ-ONLY."""
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                  wintypes.LPVOID]
    k.DeviceIoControl.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = k.CreateFileW(device_id, 0, 3, None, 3, 0, None)  # no access rights, share r/w, OPEN_EXISTING
    if handle in (None, wintypes.HANDLE(-1).value):
        return None
    try:
        length = ctypes.c_longlong(0)
        returned = wintypes.DWORD(0)
        ok = k.DeviceIoControl(handle, 0x7405C, None, 0, ctypes.byref(length), 8,
                               ctypes.byref(returned), None)
        return int(length.value) if ok and length.value > 0 else None
    finally:
        k.CloseHandle(handle)


def _probe_length(device_id: str, hint: int, _open=open) -> int | None:
    """Fallback: find the last readable sector at/after `hint` by doubling + bisection. READ-ONLY."""
    try:
        with _open(device_id, "rb", buffering=0) as f:
            def readable(off: int) -> bool:
                try:
                    f.seek(off)
                    return len(f.read(_SECTOR)) == _SECTOR
                except OSError:
                    return False

            start = max(0, hint - _SECTOR) // _SECTOR * _SECTOR
            if not readable(start):
                return None
            lo, step = start, _SECTOR
            while readable(lo + step) and step < (1 << 42):
                lo += step
                step *= 2
            hi = lo + step
            while hi - lo > _SECTOR:
                mid = (lo + hi) // 2 // _SECTOR * _SECTOR
                if mid <= lo:
                    break
                if readable(mid):
                    lo = mid
                else:
                    hi = mid
            return lo + _SECTOR
    except OSError:
        return None


def get_device_length(device_id: str, reported_bytes: int | None = None) -> int | None:
    """Real addressable length of a block device, or None if it cannot be determined.

    Windows' Win32_DiskDrive.Size can be *smaller* than the disk (a real 32 GB
    stick reported 7.5 MiB short), so sizing a wipe or a verification from it
    would leave the tail untouched/unexamined. READ-ONLY.
    """
    if platform.system() == "Windows":
        try:
            length = _windows_length_ioctl(device_id)
        except Exception:  # noqa: BLE001 - fall through to probing
            length = None
        if length:
            return length
        return _probe_length(device_id, reported_bytes) if reported_bytes else None
    try:
        with open(device_id, "rb") as f:
            return f.seek(0, 2) or None
    except OSError:
        return None


def overwrite_device_passes(
    device_id: str,
    capacity_bytes: int | None,
    passes: list[str],
) -> list[dict]:
    """Apply overwrite passes directly to a raw block device.

    Opens the device in raw binary mode and writes the same pass patterns
    (zero / one / random) used for image-based sanitization.

    Returns a list of {pass, bytes_written} records.
    """
    records: list[dict] = []

    for kind in passes:
        if kind == "zero":
            fill: bytes | None = b"\x00"
        elif kind == "one":
            fill = b"\xFF"
        elif kind == "random":
            fill = None
        else:
            raise PhysicalWipeError(f"Unknown overwrite pass kind: {kind}")

        written = 0
        try:
            # On Windows, opening \\.\PHYSICALDRIVEn in 'rb+' mode requires
            # Administrator privileges and exclusive access (device must be
            # offline / unmounted).
            # On Linux, opening /dev/sdX in 'rb+' mode requires root.
            with open(device_id, "rb+") as f:
                target_bytes = capacity_bytes or float("inf")
                while written < target_bytes:
                    n = min(_CHUNK, target_bytes - written) if capacity_bytes else _CHUNK
                    buf = os.urandom(n) if fill is None else fill * n
                    try:
                        bytes_out = f.write(buf)
                        if bytes_out == 0:
                            break
                        written += bytes_out
                    except OSError as e:
                        # On Windows, writing exactly to the end of a physical drive
                        # can sometimes yield Invalid Argument (22) or No Space Left (28).
                        # If we've written at least 99% of the capacity, we can consider
                        # it the end of the drive. Otherwise, it's a real failure.
                        import errno
                        if capacity_bytes and written >= capacity_bytes * 0.99:
                            break
                        if getattr(e, "errno", None) in (errno.ENOSPC, errno.EINVAL) and not capacity_bytes:
                            break
                        raise PhysicalWipeError(f"Write failed at offset {written}: {e}")
                
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass  # Some raw devices don't support fsync
        except PermissionError:
            raise PhysicalWipeError(
                f"Permission denied opening {device_id}. "
                "Run ZeroTrace as Administrator (Windows) or root (Linux)."
            )
        except FileNotFoundError:
            raise PhysicalWipeError(f"Device {device_id} not found. It may have been disconnected.")
        except OSError as exc:
            if written == 0:
                raise PhysicalWipeError(f"Failed to open device {device_id}: {exc}")
            # If we wrote some bytes before hitting an error, record what we got
            pass

        records.append({"pass": kind, "bytes_written": written})

    return records


_SECTOR = 4096  # read offsets/lengths are multiples of this (raw devices require alignment)
_VERIFY_SAMPLES = 16
_FULL_CHUNK = 4 * 1024 * 1024  # bounded read size for full read-back (never the whole device)
# Conservative read throughput used only to *estimate* full read-back duration.
FULL_READBACK_ASSUMED_BYTES_PER_SEC = 20 * 1024 * 1024

VERIFICATION_LIMITATIONS = {
    "sampled": (
        "Sampled verification: only the listed windows were read back. Data outside "
        "those windows was NOT examined, so this is evidence, not proof, that the whole "
        "device was overwritten. It does not cover remapped sectors, hidden areas or "
        "unaddressable flash cells."
    ),
    "full_readback": (
        "Full read-back verification: every addressable byte the device returned was "
        "read and examined. This does not show that remapped sectors, hidden or "
        "over-provisioned areas, or all physical flash cells were sanitized; device-level "
        "sanitize commands may be required for that."
    ),
}


def estimate_full_readback_seconds(capacity_bytes: int | None) -> int | None:
    """Rough duration of a full read-back (None if capacity unknown)."""
    if not capacity_bytes:
        return None
    return int(capacity_bytes / FULL_READBACK_ASSUMED_BYTES_PER_SEC) + 1


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _new_record(method: str, capacity_bytes: int | None, expect_zero: bool) -> dict:
    return {
        "method": method,  # "sampled" | "full_readback"
        "status": "inconclusive",  # verified | failed | inconclusive
        "device_capacity_bytes": capacity_bytes,
        "expected_pattern": "zero" if expect_zero else "not_checked",
        "bytes_checked": 0,
        "non_zero_bytes_found": 0,
        "short_reads": 0,
        "read_errors": [],  # [{"offset": int, "error": str}]
        "warnings": [],
        "started_at": _utc_now(),
        "completed_at": None,
        "limitations": VERIFICATION_LIMITATIONS[method],
    }


def _finish(rec: dict, complete: bool) -> dict:
    """Derive the final status. Only a *complete* read can be verified/failed."""
    rec["read_complete"] = complete
    rec["completed_at"] = _utc_now()
    if rec["read_errors"]:
        rec["verification_error"] = rec["read_errors"][0]["error"]
    elif rec["warnings"] and not complete:
        rec["verification_error"] = rec["warnings"][0]
    if not complete:
        rec["status"] = "inconclusive"
    elif rec["expected_pattern"] == "zero":
        rec["status"] = "verified" if rec["non_zero_bytes_found"] == 0 else "failed"
    else:
        rec["status"] = "verified"  # content pattern not checked; read completed
        rec["warnings"].append("Final pass is not zero-fill; only readability was confirmed.")
    return rec


def _read_exact(f, want: int) -> tuple[bytes, int]:
    """Read up to `want` bytes, retrying after short reads. Returns (data, short_read_count)."""
    parts: list[bytes] = []
    got = 0
    shorts = 0
    while got < want:
        chunk = f.read(want - got)
        if not chunk:
            break
        if len(chunk) < want - got:
            shorts += 1
        parts.append(chunk)
        got += len(chunk)
    return b"".join(parts), shorts


def _sample_offsets(capacity: int, sample_size: int, count: int) -> list[int]:
    """Evenly spaced, sector-aligned offsets covering head, body and tail."""
    last = max(0, capacity - sample_size)
    if count <= 1 or last == 0:
        return [0]
    offsets = {(last * i // (count - 1)) // _SECTOR * _SECTOR for i in range(count)}
    return sorted(offsets)


def verify_device_zeroed(
    device_id: str,
    capacity_bytes: int | None = None,
    sample_size: int = 1024 * 1024,
    expect_zero: bool = True,
    _open=open,
) -> dict:
    """Sampled read-back: `_VERIFY_SAMPLES` evenly spaced windows (head and tail
    included), placed using the capacity from discovery -- seeking to the end of
    a raw Windows disk does not report its size. READ-ONLY.

    Returns a structured verification record (see `_new_record`). Any read error,
    short read or unknown capacity yields status "inconclusive", never "verified".
    """
    rec = _new_record("sampled", capacity_bytes, expect_zero)
    rec["samples_checked"] = 0
    if not capacity_bytes or capacity_bytes < 0:
        rec["warnings"].append("Device capacity unknown; cannot place verification samples.")
        return _finish(rec, False)

    sample_size = max(_SECTOR, min(sample_size, capacity_bytes) // _SECTOR * _SECTOR)
    offsets = _sample_offsets(capacity_bytes, sample_size, _VERIFY_SAMPLES)
    rec["sample_size_bytes"] = sample_size
    rec["sample_offsets"] = offsets
    complete = True
    try:
        with _open(device_id, "rb", buffering=0) as f:
            for offset in offsets:
                f.seek(offset)
                buf, shorts = _read_exact(f, sample_size)
                rec["short_reads"] += shorts
                rec["bytes_checked"] += len(buf)
                rec["non_zero_bytes_found"] += len(buf) - buf.count(0)
                if len(buf) < sample_size:
                    rec["warnings"].append(
                        f"Incomplete read at offset {offset}: got {len(buf)} of {sample_size} bytes."
                    )
                    complete = False
                    break
                rec["samples_checked"] += 1
    except OSError as exc:
        rec["read_errors"].append({"offset": rec["bytes_checked"], "error": str(exc)})
        complete = False
    return _finish(rec, complete)


def verify_device_full_readback(
    device_id: str,
    capacity_bytes: int | None,
    expect_zero: bool = True,
    chunk_size: int = _FULL_CHUNK,
    _open=open,
) -> dict:
    """Full read-back: read the entire addressable capacity sequentially in
    bounded chunks (never holding more than one chunk in memory) and count
    non-zero bytes. READ-ONLY; never writes to the device.

    Verified only if every byte of the reported capacity was read and, for a
    zero-fill, all were zero. A read error, short/empty read before capacity,
    unknown capacity, or the device returning data past its reported capacity
    all yield "inconclusive".
    """
    rec = _new_record("full_readback", capacity_bytes, expect_zero)
    rec["chunk_size_bytes"] = chunk_size
    if not capacity_bytes or capacity_bytes < 0:
        rec["warnings"].append("Device capacity unknown; cannot perform full read-back.")
        return _finish(rec, False)

    complete = False
    try:
        with _open(device_id, "rb", buffering=0) as f:
            pos = 0
            while pos < capacity_bytes:
                want = min(chunk_size, capacity_bytes - pos)
                buf, shorts = _read_exact(f, want)
                rec["short_reads"] += shorts
                rec["bytes_checked"] += len(buf)
                rec["non_zero_bytes_found"] += len(buf) - buf.count(0)
                pos += len(buf)
                if len(buf) < want:
                    rec["warnings"].append(
                        f"Device ended early: read {pos} of {capacity_bytes} reported bytes "
                        "(capacity inconsistent with device)."
                    )
                    break
            else:
                complete = True
                # Capacity consistency: nothing should be readable past the end.
                try:
                    extra = f.read(_SECTOR)
                except OSError:
                    extra = b""  # reading past the end of a raw device may raise; that's expected
                if extra:
                    rec["warnings"].append(
                        "Device returned data beyond its reported capacity "
                        "(capacity inconsistent with device); coverage cannot be established."
                    )
                    complete = False
    except OSError as exc:
        rec["read_errors"].append({"offset": rec["bytes_checked"], "error": str(exc)})
        complete = False
    return _finish(rec, complete)
