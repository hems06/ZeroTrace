"""Verification engine.

Produces a structured, honest verification result for a sanitization
operation. Distinguishes "the overwrite command completed" from
"independently verified sanitized" -- the latter requires markers to be
absent AND the hash to have changed AND (for image targets) the original to
be provably untouched.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

VERIFIED = "verified"
FAILED = "failed"
INCONCLUSIVE = "inconclusive"

# Full-file substring scanning is only feasible at the small scale used for
# demo/test images. Real multi-GB/TB devices would need targeted sampling
# (per NIST SP 800-88 guidance on representative sampling) rather than a
# full-content scan -- this cap documents that boundary honestly instead of
# silently hanging on a large file.
MAX_FULL_SCAN_BYTES = 256 * 1024 * 1024


@dataclass
class VerificationResult:
    status: str
    markers_found_before: int
    markers_found_after: int
    pre_hash: str
    post_hash: str
    hash_changed: bool
    original_untouched: bool | None
    limitations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "markers_found_before": self.markers_found_before,
            "markers_found_after": self.markers_found_after,
            "pre_hash": self.pre_hash,
            "post_hash": self.post_hash,
            "hash_changed": self.hash_changed,
            "original_untouched": self.original_untouched,
            "limitations": self.limitations,
            "warnings": self.warnings,
        }


def count_markers_present(path: Path, markers: list[dict]) -> int:
    size = path.stat().st_size
    if size > MAX_FULL_SCAN_BYTES:
        raise ValueError(
            f"File too large for full-content marker verification ({size} bytes > "
            f"{MAX_FULL_SCAN_BYTES} byte demo-scale cap)."
        )
    data = path.read_bytes()
    found = 0
    for marker in markers:
        marker_hash = marker["marker_sha256"]
        # We don't have the plaintext marker bytes here by design (manifest
        # stores only their hash); instead re-derive presence by hashing a
        # sliding window at/around the recorded offset region.
        offset = marker["offset"]
        length = marker["length"]
        window_start = max(0, offset - 64)
        window_end = min(size, offset + length + 64)
        window = data[window_start:window_end]
        for i in range(0, len(window) - length + 1):
            if hashlib.sha256(window[i : i + length]).hexdigest() == marker_hash:
                found += 1
                break
    return found


def verify_image_operation(
    *,
    working_copy_path: Path,
    pre_hash: str,
    markers: list[dict],
    markers_before: int,
    original_image_path: Path,
    original_sha256_at_discovery: str,
) -> VerificationResult:
    from app.utils.hashing import sha256_file

    warnings: list[str] = []
    limitations = [
        "Marker presence is checked via hashed sliding-window comparison around "
        "recorded offsets, not full plaintext signature scanning.",
        "Full-content verification is only performed at demo/test scale "
        f"(<= {MAX_FULL_SCAN_BYTES} bytes); real devices require representative "
        "sampling rather than a full scan.",
    ]

    post_hash = sha256_file(working_copy_path)
    hash_changed = post_hash != pre_hash

    try:
        markers_after = count_markers_present(working_copy_path, markers)
    except ValueError as exc:
        warnings.append(str(exc))
        markers_after = -1

    original_untouched = sha256_file(original_image_path) == original_sha256_at_discovery
    if not original_untouched:
        warnings.append("CRITICAL: original image hash no longer matches discovery-time hash.")

    if not original_untouched:
        status = FAILED
    elif markers_after == -1:
        status = INCONCLUSIVE
    elif markers_after == 0 and hash_changed:
        status = VERIFIED
    elif markers_after > 0:
        status = FAILED
        warnings.append(f"{markers_after} marker(s) still detected after sanitization.")
    else:
        status = INCONCLUSIVE
        warnings.append("Hash did not change after the sanitization pass.")

    return VerificationResult(
        status=status,
        markers_found_before=markers_before,
        markers_found_after=max(markers_after, 0),
        pre_hash=pre_hash,
        post_hash=post_hash,
        hash_changed=hash_changed,
        original_untouched=original_untouched,
        limitations=limitations,
        warnings=warnings,
    )
