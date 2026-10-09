"""Low-level overwrite primitive shared by demo and image-based sanitization.

Operates only on the file path it is given -- callers are responsible for
ensuring that path is an isolated working copy, never the original image or
a live device.
"""
from __future__ import annotations

import os
from pathlib import Path

_CHUNK = 1024 * 1024


def _pass_byte(kind: str) -> bytes | None:
    if kind == "zero":
        return b"\x00"
    if kind == "one":
        return b"\xFF"
    if kind == "random":
        return None  # signals os.urandom per chunk
    raise ValueError(f"Unknown overwrite pass kind: {kind}")


def overwrite_file_passes(path: Path, passes: list[str]) -> list[dict]:
    """Apply each overwrite pass (in order) to the full contents of path.

    Returns a list of {"pass": kind, "bytes_written": n} records.
    """
    size = path.stat().st_size
    records = []
    for kind in passes:
        fill = _pass_byte(kind)
        written = 0
        with open(path, "r+b") as f:
            f.seek(0)
            while written < size:
                remaining = size - written
                n = min(_CHUNK, remaining)
                buf = os.urandom(n) if fill is None else fill * n
                f.write(buf)
                written += n
            f.flush()
            os.fsync(f.fileno())
        records.append({"pass": kind, "bytes_written": written})
    return records
