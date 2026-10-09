"""Physical storage device discovery.

Read-only enumeration of storage devices on the host OS, for display and
operator review purposes. This module never writes to a device; it only
reports what the OS exposes so the operator can review a target before any
sanitization decision is made.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
from dataclasses import dataclass, field

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


@dataclass
class PhysicalDevice:
    device_id: str
    name: str
    capacity_bytes: int | None
    interface: str | None
    media_type: str | None
    is_system_disk: bool
    is_mounted: bool
    mount_points: list[str] = field(default_factory=list)
    partitions: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "name": self.name,
            "capacity_bytes": self.capacity_bytes,
            "interface": self.interface,
            "media_type": self.media_type,
            "is_system_disk": self.is_system_disk,
            "is_mounted": self.is_mounted,
            "mount_points": self.mount_points,
            "partitions": self.partitions,
        }


def _mounted_roots() -> set[str]:
    """Best-effort set of mount points / drive letters that host the running
    OS or this application, used to block accidental selection of the
    system disk."""
    roots: set[str] = set()
    if psutil is None:
        return roots
    try:
        for part in psutil.disk_partitions(all=False):
            if "rw" in part.opts or part.fstype:
                roots.add(part.mountpoint)
    except Exception:
        pass
    return roots


def _run_powershell(ps_cmd: str, timeout: int = 20) -> tuple[str, str | None]:
    """Run a PowerShell command, returning (stdout, error_message).

    error_message is None on success (even if stdout is legitimately empty);
    otherwise it describes exactly what went wrong so callers can surface it
    instead of silently reporting "no devices found".
    """
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return "", "PowerShell was not found on PATH; cannot enumerate physical devices on this system."
    except subprocess.TimeoutExpired:
        return "", f"Device enumeration command timed out after {timeout}s."
    except OSError as exc:
        return "", f"Could not launch PowerShell: {exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        return "", f"PowerShell exited with code {result.returncode}: {stderr[:300] or '(no stderr output)'}"
    return result.stdout.strip(), None


def _windows_disk_partitions() -> tuple[dict[int, list[str]], str | None]:
    """Map disk index -> list of drive letters currently assigned to it,
    via Get-Partition. Used for both system-disk detection and accurate
    is_mounted/mount_points reporting (a raw/unformatted or unassigned
    drive legitimately has none)."""
    raw, error = _run_powershell(
        "Get-Partition -ErrorAction SilentlyContinue | "
        "Select-Object DiskNumber,DriveLetter | ConvertTo-Json"
    )
    if error:
        return {}, error
    if not raw:
        return {}, None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {}, f"Could not parse partition list: {exc}"
    if isinstance(data, dict):
        data = [data]

    by_disk: dict[int, list[str]] = {}
    for entry in data:
        disk_number = entry.get("DiskNumber")
        letter = entry.get("DriveLetter")
        if disk_number is None or not letter or letter == " ":
            continue
        by_disk.setdefault(int(disk_number), []).append(f"{letter}:\\")
    return by_disk, None


def _windows_devices() -> tuple[list[PhysicalDevice], list[str]]:
    devices: list[PhysicalDevice] = []
    warnings: list[str] = []

    raw, error = _run_powershell(
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object DeviceID,Caption,Size,InterfaceType,MediaType,Index | "
        "ConvertTo-Json"
    )
    if error:
        warnings.append(f"Physical device enumeration failed: {error}")
        return devices, warnings
    if not raw:
        warnings.append(
            "The OS reported zero disk drives (Get-CimInstance Win32_DiskDrive returned "
            "nothing). If a drive is plugged in but not showing, check that it appears in "
            "Windows Disk Management -- devices that only expose an MTP/media-transfer "
            "interface (e.g. many phones) are not block storage devices and won't appear here."
        )
        return devices, warnings

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        warnings.append(f"Could not parse device list from PowerShell output: {exc}")
        return devices, warnings
    if isinstance(data, dict):
        data = [data]

    drive_letters_by_disk, partition_error = _windows_disk_partitions()
    if partition_error:
        warnings.append(f"Could not determine mount/partition status: {partition_error}")

    system_drive_letter = None
    try:
        import os

        system_drive_letter = (os.environ.get("SystemDrive", "") or "")[:1].upper()
    except Exception:
        pass

    for entry in data:
        index = entry.get("Index")
        mount_points = drive_letters_by_disk.get(index, []) if index is not None else []
        is_system = bool(
            system_drive_letter
            and any(mp.upper().startswith(system_drive_letter) for mp in mount_points)
        )
        devices.append(
            PhysicalDevice(
                device_id=str(entry.get("DeviceID") or f"\\\\.\\PHYSICALDRIVE{index}"),
                name=str(entry.get("Caption") or "Unknown disk"),
                capacity_bytes=int(entry["Size"]) if entry.get("Size") else None,
                interface=entry.get("InterfaceType"),
                media_type=entry.get("MediaType"),
                is_system_disk=is_system,
                is_mounted=bool(mount_points),
                mount_points=mount_points,
            )
        )

    return devices, warnings


def _linux_devices() -> tuple[list[PhysicalDevice], list[str]]:
    devices: list[PhysicalDevice] = []
    warnings: list[str] = []
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-O"],
            capture_output=True, text=True, timeout=20,
        )
    except FileNotFoundError:
        return devices, ["'lsblk' was not found on PATH; cannot enumerate physical devices."]
    except subprocess.TimeoutExpired:
        return devices, ["Device enumeration command ('lsblk') timed out after 20s."]

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        return devices, [f"'lsblk' exited with code {result.returncode}: {stderr[:300] or '(no stderr output)'}"]

    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        return devices, [f"Could not parse 'lsblk' output: {exc}"]

    for entry in data.get("blockdevices", []):
        if entry.get("type") != "disk":
            continue
        mountpoints = [c.get("mountpoint") for c in entry.get("children", []) if c.get("mountpoint")]
        is_system = any(mp in ("/", "/boot", "/boot/efi") for mp in mountpoints)
        devices.append(
            PhysicalDevice(
                device_id=f"/dev/{entry['name']}",
                name=entry.get("model") or entry["name"],
                capacity_bytes=int(entry["size"]) if str(entry.get("size", "")).isdigit() else None,
                interface=entry.get("tran"),
                media_type="SSD" if entry.get("rota") == "0" else "HDD",
                is_system_disk=is_system,
                is_mounted=bool(mountpoints),
                mount_points=mountpoints,
                partitions=[
                    {
                        "name": c.get("name"),
                        "size": c.get("size"),
                        "mountpoint": c.get("mountpoint"),
                        "fstype": c.get("fstype"),
                    }
                    for c in entry.get("children", [])
                ],
            )
        )
    if not devices and not warnings:
        warnings.append("'lsblk' reported no disk-type block devices.")
    return devices, warnings


def discover_physical_devices_detailed() -> tuple[list[PhysicalDevice], list[str]]:
    """Like discover_physical_devices(), but also returns human-readable
    warnings explaining any enumeration failure instead of swallowing it."""
    system = platform.system()
    if system == "Windows":
        return _windows_devices()
    if system == "Linux":
        return _linux_devices()
    return [], [f"Physical device discovery is not implemented for platform '{system}'."]


def discover_physical_devices() -> list[PhysicalDevice]:
    devices, _warnings = discover_physical_devices_detailed()
    return devices


_SAFE_DEVICE_ID = re.compile(r"^[A-Za-z0-9_\\/.:-]+$")


def is_known_device_id(device_id: str) -> bool:
    return bool(_SAFE_DEVICE_ID.match(device_id)) and len(device_id) < 256
