"""Shared synthetic test-data generation.

Used both by the standalone demo-image generator script and by
demonstration-mode sanitization (which needs an isolated throwaway dataset
to operate on, never touching real files).
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

SYNTHETIC_MARKERS = [
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0001::employee_ssn=000-11-SAMPLE",
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0002::credit_card=4111-TEST-ONLY-0002",
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0003::patient_record=DEMO-PHI-DATA-0003",
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0004::api_secret=sk_demo_not_real_0004",
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0005::source_code_snippet=DEMO-IP-0005",
]


# 1 MiB fill writes keep multi-gigabyte image generation reasonably fast while
# still letting us place markers at exact byte offsets.
_FILL_CHUNK = 1024 * 1024


def _try_make_sparse(f) -> bool:
    """Best-effort: mark an open file sparse on Windows (NTFS) so that a region
    left unwritten by a later ``truncate`` consumes no real disk space.

    Returns True if the sparse flag was set. A no-op (returns False) on other
    platforms or if the ioctl is unavailable -- the file is still correct,
    just not sparse.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        FSCTL_SET_SPARSE = 0x000900C4
        handle = msvcrt.get_osfhandle(f.fileno())
        returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            wintypes.HANDLE(handle),
            FSCTL_SET_SPARSE,
            None,
            0,
            None,
            0,
            ctypes.byref(returned),
            None,
        )
        return bool(ok)
    except Exception:  # noqa: BLE001 - sparseness is an optimization, never required
        return False


def _punch_zero_tail(f, start: int, end: int) -> None:
    """Deallocate the byte range [start, end) on a sparse NTFS file so it reads
    as zeros without consuming disk. Best-effort; a no-op off Windows."""
    if sys.platform != "win32" or end <= start:
        return
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        FSCTL_SET_ZERO_DATA = 0x000980C8

        class FILE_ZERO_DATA_INFORMATION(ctypes.Structure):
            _fields_ = [("FileOffset", ctypes.c_longlong), ("BeyondFinalZero", ctypes.c_longlong)]

        info = FILE_ZERO_DATA_INFORMATION(start, end)
        handle = msvcrt.get_osfhandle(f.fileno())
        returned = wintypes.DWORD(0)
        ctypes.windll.kernel32.DeviceIoControl(
            wintypes.HANDLE(handle),
            FSCTL_SET_ZERO_DATA,
            ctypes.byref(info),
            ctypes.sizeof(info),
            None,
            0,
            ctypes.byref(returned),
            None,
        )
    except Exception:  # noqa: BLE001 - sparseness is an optimization, never required
        pass


def build_synthetic_file(out_path: Path, size_bytes: int, data_bytes: int | None = None) -> dict:
    """Write a disk image of ``size_bytes`` whose first ``data_bytes`` hold
    filler + embedded synthetic markers, with any remainder left as a sparse
    zero-filled tail. Returns a manifest describing the markers.

    When ``data_bytes`` is None (or >= ``size_bytes``) the whole image is
    filled. A smaller ``data_bytes`` models a large-capacity disk that only
    holds a little real data (e.g. a 32 GB disk with 500 MB of data); the
    empty tail is made sparse where the OS supports it (NTSFS), so generation
    uses only ~``data_bytes`` of disk. Markers are placed at exact offsets
    (``data * k / 6`` for k=1..5) within the data region.

    The content hash is computed inline as the file is written (real bytes
    then zero tail), so no second full read is needed.
    """
    if data_bytes is None or data_bytes > size_bytes:
        data_bytes = size_bytes

    fill_pattern = b"ZEROTRACE-DEMO-FILLER-BLOCK-"
    block = (fill_pattern * (_FILL_CHUNK // len(fill_pattern) + 1))[:_FILL_CHUNK]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    markers_meta = []
    marker_positions = [
        int(data_bytes * (i + 1) / (len(SYNTHETIC_MARKERS) + 1))
        for i in range(len(SYNTHETIC_MARKERS))
    ]
    sha256 = hashlib.sha256()

    with open(out_path, "wb") as f:
        sparse = _try_make_sparse(f) if size_bytes > data_bytes else False
        written = 0

        def _write(buf: bytes) -> None:
            nonlocal written
            f.write(buf)
            sha256.update(buf)
            written += len(buf)

        def _fill_to(target: int) -> None:
            while written < target:
                _write(block[: min(len(block), target - written)])

        for marker_idx, marker in enumerate(SYNTHETIC_MARKERS):
            _fill_to(marker_positions[marker_idx])
            offset = written
            _write(marker)
            markers_meta.append(
                {
                    "offset": offset,
                    "length": len(marker),
                    "marker_sha256": hashlib.sha256(marker).hexdigest(),
                    "label": f"synthetic-sensitive-record-{marker_idx + 1}",
                }
            )
        _fill_to(data_bytes)

        # Extend to full capacity, then (on NTFS) punch out the tail so it is a
        # true sparse zero region. The hash still covers the whole logical file.
        data_end = written
        f.flush()
        f.truncate(size_bytes)
        if sparse:
            _punch_zero_tail(f, data_end, size_bytes)

    tail = size_bytes - data_end
    zero = bytes(8 * 1024 * 1024)
    while tail > 0:
        n = min(len(zero), tail)
        sha256.update(zero[:n])
        tail -= n

    return {
        "description": "Synthetic demo dataset. Contains no real sensitive data.",
        "media_type_label": "disk-image",
        "size_bytes": size_bytes,
        "data_bytes": data_bytes,
        "sparse": sparse,
        "original_sha256": sha256.hexdigest(),
        "markers": markers_meta,
    }
