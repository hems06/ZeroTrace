"""Generate synthetic sample disk image(s) for image-based testing.

This creates raw ``.img`` files that stand in for extracted storage-device
images, with several "sensitive" marker records written at known byte offsets,
plus a sidecar ``.manifest.json`` describing those offsets. The sanitization/
verification engines use the manifest to check whether markers are present
(pre-wipe) or absent (post-wipe) without needing a full filesystem parser.

No real personal or sensitive data is used -- all markers are clearly
synthetic placeholders.

Usage:
    # Single image, size as megabytes (back-compatible):
    python demo_data/generate_sample_image.py --size-mb 8

    # Single image, human-friendly size:
    python demo_data/generate_sample_image.py --size 30mb --out my_disk.img

    # The standard test set (30 MB, 1 GB, 2 GB) in one go:
    python demo_data/generate_sample_image.py --standard-set
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.devices.synthetic import build_synthetic_file  # noqa: E402

# Default sizes requested for the demo/test corpus.
STANDARD_SET = ["30mb", "1gb", "2gb"]

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?\s*$", re.IGNORECASE)
_UNIT_BYTES = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3}


def parse_size(text: str) -> int:
    """Parse a human-friendly size like '30mb', '1gb', '2048' (MB assumed when
    no unit is given) into a byte count."""
    m = _SIZE_RE.match(text)
    if not m:
        raise argparse.ArgumentTypeError(f"Unrecognised size: {text!r} (try '30mb', '1gb', '2gb').")
    value = float(m.group(1))
    unit = (m.group(2) or "mb").lower()
    size = int(value * _UNIT_BYTES[unit])
    if size <= 0:
        raise argparse.ArgumentTypeError(f"Size must be positive: {text!r}")
    return size


def _human(size_bytes: int) -> str:
    if size_bytes >= _UNIT_BYTES["gb"] and size_bytes % _UNIT_BYTES["gb"] == 0:
        return f"{size_bytes // _UNIT_BYTES['gb']}gb"
    return f"{size_bytes // _UNIT_BYTES['mb']}mb"


def _default_name(size_bytes: int, data_bytes: int | None = None) -> str:
    """Produce a stable, readable filename for a given size."""
    if data_bytes is not None and data_bytes < size_bytes:
        return f"sample_disk_{_human(size_bytes)}_{_human(data_bytes)}data.img"
    return f"sample_disk_{_human(size_bytes)}.img"


def generate(out_path: Path, size_bytes: int, data_bytes: int | None = None) -> None:
    manifest = build_synthetic_file(out_path, size_bytes, data_bytes)
    manifest_path = out_path.with_suffix(out_path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"Created sample image: {out_path} ({manifest['size_bytes']:,} bytes)")
    print(f"  Data region: {manifest['data_bytes']:,} bytes (sparse tail: {manifest['sparse']})")
    print(f"  SHA-256: {manifest['original_sha256']}")
    print(f"  Markers embedded: {len(manifest['markers'])}")
    print(f"  Manifest: {manifest_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=None, help="Output path (defaults to a size-derived name under images_dir).")
    parser.add_argument("--size", type=parse_size, default=None, help="Image size, e.g. '30mb', '1gb', '2gb', '32gb'.")
    parser.add_argument("--size-mb", type=int, default=None, help="Image size in megabytes (legacy).")
    parser.add_argument(
        "--data",
        type=parse_size,
        default=None,
        help="Bytes of real data to write (e.g. '500mb'); the rest of --size is a sparse zero tail.",
    )
    parser.add_argument(
        "--standard-set",
        action="store_true",
        help=f"Generate the standard corpus ({', '.join(STANDARD_SET)}) into images_dir.",
    )
    args = parser.parse_args()

    settings.images_dir.mkdir(parents=True, exist_ok=True)

    if args.standard_set:
        if args.out or args.data is not None:
            parser.error("--out / --data cannot be combined with --standard-set.")
        for spec in STANDARD_SET:
            size_bytes = parse_size(spec)
            generate(settings.images_dir / _default_name(size_bytes), size_bytes)
        return

    if args.size is not None and args.size_mb is not None:
        parser.error("Pass either --size or --size-mb, not both.")

    if args.size is not None:
        size_bytes = args.size
    elif args.size_mb is not None:
        size_bytes = args.size_mb * _UNIT_BYTES["mb"]
    else:
        size_bytes = 8 * _UNIT_BYTES["mb"]  # back-compatible default

    data_bytes = args.data
    if data_bytes is not None and data_bytes > size_bytes:
        parser.error(f"--data ({data_bytes} bytes) cannot exceed --size ({size_bytes} bytes).")

    out_path = Path(args.out) if args.out else settings.images_dir / _default_name(size_bytes, data_bytes)
    generate(out_path, size_bytes, data_bytes)


if __name__ == "__main__":
    main()
