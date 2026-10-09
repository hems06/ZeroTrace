"""Image-backed test target discovery and validation.

Disk images used for testing live under ``settings.images_dir``. Operators
reference an image by filename only (never a raw filesystem path) and this
module resolves + validates that name against the allow-listed directory,
which is what prevents path traversal / arbitrary filesystem access from the
API surface.
"""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.config import settings
from app.utils.hashing import sha256_file

IMAGE_EXTENSIONS = {".img", ".bin", ".dd"}
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


class InvalidImageReference(ValueError):
    pass


@dataclass
class ImageTarget:
    identifier: str  # filename, used as the public identifier
    path: Path
    size_bytes: int
    sha256: str
    manifest: dict

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "target_type": "image",
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "marker_count": len(self.manifest.get("markers", [])),
            "media_type_label": self.manifest.get("media_type_label", "disk-image"),
            "description": self.manifest.get("description", ""),
        }


def _manifest_path(image_path: Path) -> Path:
    return image_path.with_suffix(image_path.suffix + ".manifest.json")


def list_images() -> list[dict]:
    """List available image-backed test targets (metadata only, no copying)."""
    out = []
    images_dir = settings.images_dir
    if not images_dir.exists():
        return out
    for path in sorted(images_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in IMAGE_EXTENSIONS:
            continue
        manifest = _read_manifest(path)
        out.append(
            {
                "identifier": path.name,
                "target_type": "image",
                "size_bytes": path.stat().st_size,
                "marker_count": len(manifest.get("markers", [])),
                "media_type_label": manifest.get("media_type_label", "disk-image"),
                "description": manifest.get("description", ""),
            }
        )
    return out


def _read_manifest(image_path: Path) -> dict:
    manifest_path = _manifest_path(image_path)
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def resolve_image(identifier: str) -> ImageTarget:
    """Resolve + validate an operator-supplied image identifier.

    Raises InvalidImageReference for anything that looks like path
    traversal, an absolute path, an unsupported extension, or a file that
    does not exist inside the allow-listed images directory.
    """
    if not identifier or not _SAFE_NAME.match(identifier):
        raise InvalidImageReference(
            "Image identifier must be a plain filename (letters, digits, '.', '_', '-' only)."
        )

    candidate = (settings.images_dir / identifier).resolve()
    images_root = settings.images_dir.resolve()
    if images_root not in candidate.parents and candidate != images_root:
        raise InvalidImageReference("Resolved path escapes the allow-listed images directory.")
    if candidate.suffix.lower() not in IMAGE_EXTENSIONS:
        raise InvalidImageReference(f"Unsupported image format: {candidate.suffix}")
    if not candidate.is_file():
        raise InvalidImageReference(f"Image '{identifier}' was not found.")

    manifest = _read_manifest(candidate)
    return ImageTarget(
        identifier=identifier,
        path=candidate,
        size_bytes=candidate.stat().st_size,
        sha256=sha256_file(candidate),
        manifest=manifest,
    )


def make_working_copy(image: ImageTarget, operation_id: str) -> Path:
    """Copy the image into the workspace for destructive testing.

    The original image under images_dir is never opened for writing by any
    sanitization routine -- only this copy is. Returns the working copy path.
    """
    settings.workspace_dir.mkdir(parents=True, exist_ok=True)
    working_copy = settings.workspace_dir / f"{operation_id}__{image.path.name}"
    shutil.copy2(image.path, working_copy)
    return working_copy


def assert_original_untouched(image: ImageTarget) -> bool:
    """Re-hash the original image and confirm it matches the hash recorded
    at discovery time. Used as a safety check after every image operation."""
    current_hash = sha256_file(image.path)
    return current_hash == image.sha256
