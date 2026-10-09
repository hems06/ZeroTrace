"""Shared synthetic test-data generation.

Used both by the standalone demo-image generator script and by
demonstration-mode sanitization (which needs an isolated throwaway dataset
to operate on, never touching real files).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

SYNTHETIC_MARKERS = [
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0001::employee_ssn=000-11-SAMPLE",
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0002::credit_card=4111-TEST-ONLY-0002",
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0003::patient_record=DEMO-PHI-DATA-0003",
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0004::api_secret=sk_demo_not_real_0004",
    b"SYNTHETIC-CONFIDENTIAL-RECORD-0005::source_code_snippet=DEMO-IP-0005",
]


def build_synthetic_file(out_path: Path, size_bytes: int) -> dict:
    """Write a filler-patterned file of size_bytes with embedded synthetic
    markers at spread-out offsets, returning a manifest describing them."""
    fill_pattern = b"ZEROTRACE-DEMO-FILLER-BLOCK-"
    block = (fill_pattern * (4096 // len(fill_pattern) + 1))[:4096]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    markers_meta = []
    marker_positions = [
        int(size_bytes * (i + 1) / (len(SYNTHETIC_MARKERS) + 1))
        for i in range(len(SYNTHETIC_MARKERS))
    ]

    with open(out_path, "wb") as f:
        written = 0
        marker_idx = 0
        while written < size_bytes:
            remaining = size_bytes - written
            chunk = block[: min(len(block), remaining)]
            f.write(chunk)
            written += len(chunk)

            if marker_idx < len(SYNTHETIC_MARKERS) and written >= marker_positions[marker_idx]:
                marker = SYNTHETIC_MARKERS[marker_idx]
                offset = written
                f.write(marker)
                written += len(marker)
                markers_meta.append(
                    {
                        "offset": offset,
                        "length": len(marker),
                        "marker_sha256": hashlib.sha256(marker).hexdigest(),
                        "label": f"synthetic-sensitive-record-{marker_idx + 1}",
                    }
                )
                marker_idx += 1

        f.truncate(size_bytes)

    sha256 = hashlib.sha256()
    with open(out_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            sha256.update(chunk)

    return {
        "description": "Synthetic demo dataset. Contains no real sensitive data.",
        "media_type_label": "disk-image",
        "size_bytes": size_bytes,
        "original_sha256": sha256.hexdigest(),
        "markers": markers_meta,
    }
