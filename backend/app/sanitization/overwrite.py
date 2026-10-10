"""Low-level overwrite primitive shared by demo and image-based sanitization.

Operates only on the file path it is given -- callers are responsible for
ensuring that path is an isolated working copy, never the original image or
a live device.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

_CHUNK = 1024 * 1024

# progress_cb(pass_index, pass_total, kind, pass_bytes_done, pass_bytes_total)
ProgressCb = Callable[[int, int, str, int, int], None]


def _pass_byte(kind: str) -> bytes | None:
    if kind == "zero":
        return b"\x00"
    if kind == "one":
        return b"\xFF"
    if kind == "random":
        return None  # signals os.urandom per chunk
    raise ValueError(f"Unknown overwrite pass kind: {kind}")


def overwrite_file_passes(path: Path, passes: list[str], progress_cb: Optional[ProgressCb] = None) -> list[dict]:
    """Apply each overwrite pass (in order) to the full contents of path.

    If ``progress_cb`` is given it is called as bytes are written so callers
    can report live progress / time-remaining; it never affects the wipe.

    Returns a list of {"pass": kind, "bytes_written": n} records.
    """
    size = path.stat().st_size
    pass_total = len(passes)
    records = []
    for index, kind in enumerate(passes, start=1):
        fill = _pass_byte(kind)
        written = 0
        if progress_cb is not None:
            progress_cb(index, pass_total, kind, 0, size)
        with open(path, "r+b") as f:
            f.seek(0)
            while written < size:
                remaining = size - written
                n = min(_CHUNK, remaining)
                buf = os.urandom(n) if fill is None else fill * n
                f.write(buf)
                written += n
                if progress_cb is not None:
                    progress_cb(index, pass_total, kind, written, size)
            f.flush()
            os.fsync(f.fileno())
        records.append({"pass": kind, "bytes_written": written})
    return records
