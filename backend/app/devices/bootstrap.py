"""First-run demo data bootstrap.

A packaged build has no terminal to run demo_data/generate_sample_image.py
from, so the sample image is generated automatically into the writable
images directory the first time the app starts, if no image is present yet.
This never touches a real device and never runs any sanitization.
"""
from __future__ import annotations

import json

from app.config import settings
from app.devices.images import IMAGE_EXTENSIONS
from app.devices.synthetic import build_synthetic_file


def ensure_sample_image() -> None:
    images_dir = settings.images_dir
    images_dir.mkdir(parents=True, exist_ok=True)
    has_image = any(p.suffix.lower() in IMAGE_EXTENSIONS for p in images_dir.iterdir() if p.is_file())
    if has_image:
        return

    sample_path = images_dir / "sample_disk.img"
    manifest = build_synthetic_file(sample_path, 8 * 1024 * 1024)
    manifest_path = sample_path.with_suffix(sample_path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
