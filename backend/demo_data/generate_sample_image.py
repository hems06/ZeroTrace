"""Generate a synthetic sample disk image for image-based testing.

This creates a raw ``.img`` file that stands in for an extracted
storage-device image, with several "sensitive" marker records written at
known byte offsets, plus a sidecar ``.manifest.json`` describing those
offsets. The sanitization/verification engines use the manifest to check
whether markers are present (pre-wipe) or absent (post-wipe) without needing
a full filesystem parser.

No real personal or sensitive data is used -- all markers are clearly
synthetic placeholders.

Usage:
    python demo_data/generate_sample_image.py [--out PATH] [--size-mb N]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.devices.synthetic import build_synthetic_file  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(settings.images_dir / "sample_disk.img"))
    parser.add_argument("--size-mb", type=int, default=8)
    args = parser.parse_args()

    out_path = Path(args.out)
    manifest = build_synthetic_file(out_path, args.size_mb * 1024 * 1024)
    manifest_path = out_path.with_suffix(out_path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"Created sample image: {out_path} ({manifest['size_bytes']} bytes)")
    print(f"SHA-256: {manifest['original_sha256']}")
    print(f"Markers embedded: {len(manifest['markers'])}")
    print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
