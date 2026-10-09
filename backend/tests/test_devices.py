from __future__ import annotations

import pytest

from app.devices import images as image_lib


def test_resolve_image_success(sample_image):
    target = image_lib.resolve_image(sample_image)
    assert target.identifier == sample_image
    assert target.size_bytes == 2 * 1024 * 1024
    assert len(target.manifest["markers"]) == 5
    assert len(target.sha256) == 64


def test_resolve_image_rejects_path_traversal(sample_image):
    with pytest.raises(image_lib.InvalidImageReference):
        image_lib.resolve_image("../test_disk.img")


def test_resolve_image_rejects_absolute_path(sample_image):
    with pytest.raises(image_lib.InvalidImageReference):
        image_lib.resolve_image("/etc/passwd")


def test_resolve_image_rejects_unsupported_extension(sample_image, tmp_path):
    from app.config import settings

    bad = settings.images_dir / "not_an_image.txt"
    bad.write_text("hello")
    with pytest.raises(image_lib.InvalidImageReference):
        image_lib.resolve_image("not_an_image.txt")


def test_resolve_image_missing_file():
    with pytest.raises(image_lib.InvalidImageReference):
        image_lib.resolve_image("does_not_exist.img")


def test_list_images_includes_sample(sample_image):
    listing = image_lib.list_images()
    identifiers = [i["identifier"] for i in listing]
    assert sample_image in identifiers


def test_working_copy_does_not_mutate_original(sample_image):
    target = image_lib.resolve_image(sample_image)
    original_hash_before = target.sha256
    working_copy = image_lib.make_working_copy(target, "OP-TESTCOPY")
    assert working_copy.exists()
    assert working_copy != target.path

    # Mutate the working copy only.
    with open(working_copy, "r+b") as f:
        f.write(b"\x00" * 1024)

    assert image_lib.assert_original_untouched(target) is True
    reresolved = image_lib.resolve_image(sample_image)
    assert reresolved.sha256 == original_hash_before
    working_copy.unlink()
