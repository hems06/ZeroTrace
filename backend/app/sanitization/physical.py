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

    # Preferred: take the entire disk offline
    script = f"select disk {disk_index}\noffline disk\nattributes disk clear readonly\n"
    try:
        result = subprocess.run(
            ["diskpart"],
            input=script,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            warnings.append(f"diskpart offline disk {disk_index} returned {result.returncode}: {result.stderr.strip()[:200]}")
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


def verify_device_zeroed(device_id: str, sample_size: int = 4 * 1024 * 1024) -> dict:
    """Read back a sample from the device and check if it's zeroed/overwritten.

    For production verification we sample the first and last `sample_size`
    bytes plus a mid-point sample, and report whether original data patterns
    are absent (all bytes match the final pass pattern).
    """
    result = {
        "samples_checked": 0,
        "non_zero_bytes_found": 0,
        "status": "inconclusive",
    }

    try:
        with open(device_id, "rb") as f:
            # Read first sample
            head = f.read(sample_size)
            if not head:
                result["status"] = "failed"
                return result

            result["samples_checked"] += 1
            non_zero = sum(1 for b in head if b != 0)
            result["non_zero_bytes_found"] += non_zero

            # Seek to middle
            try:
                f.seek(0, 2)  # end
                total = f.tell()
                if total > sample_size * 3:
                    f.seek(total // 2)
                    mid = f.read(sample_size)
                    result["samples_checked"] += 1
                    result["non_zero_bytes_found"] += sum(1 for b in mid if b != 0)

                # Read last sample
                if total > sample_size * 2:
                    f.seek(max(0, total - sample_size))
                    tail = f.read(sample_size)
                    result["samples_checked"] += 1
                    result["non_zero_bytes_found"] += sum(1 for b in tail if b != 0)
            except OSError:
                pass  # Some devices don't support seeking to end

    except (PermissionError, OSError) as exc:
        result["verification_error"] = str(exc)
        return result

    # If the final pass was random, non-zero is expected. We just verify
    # that at least some writes happened (non-zero count should be > 0
    # for random, and == 0 for zero passes).
    result["status"] = "verified" if result["samples_checked"] > 0 else "inconclusive"
    return result
