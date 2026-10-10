from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

TEST_INSTANCE = BACKEND_DIR / "instance_test"
if TEST_INSTANCE.exists():
    shutil.rmtree(TEST_INSTANCE)
TEST_INSTANCE.mkdir(parents=True)

os.environ["ZEROTRACE_DATABASE_URL"] = f"sqlite:///{(TEST_INSTANCE / 'test.db').as_posix()}"
os.environ["ZEROTRACE_IMAGES_DIR"] = str(TEST_INSTANCE / "images")
os.environ["ZEROTRACE_WORKSPACE_DIR"] = str(TEST_INSTANCE / "workspace")
os.environ["ZEROTRACE_CERTIFICATES_DIR"] = str(TEST_INSTANCE / "certificates")
os.environ["ZEROTRACE_KEYS_DIR"] = str(TEST_INSTANCE / "keys")
os.environ["ZEROTRACE_OPERATOR_KEYS"] = "test-operator:test-token"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.devices.synthetic import build_synthetic_file  # noqa: E402
from app.main import app  # noqa: E402

init_db()


@pytest.fixture(autouse=True)
def _drain_operations():
    """Operations now execute on a background thread sharing this one DB file.
    Wait for any still-running wipe to finish after each test so threads never
    outlive their test and contaminate the next one's view of the DB."""
    import time

    from app.models import Operation

    yield
    deadline = time.time() + 20.0
    while time.time() < deadline:
        session = SessionLocal()
        try:
            pending = (
                session.query(Operation)
                .filter(Operation.status.in_(("pending", "running")))
                .count()
            )
        finally:
            session.close()
        if pending == 0:
            return
        time.sleep(0.02)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture()
def auth_headers() -> dict:
    return {"X-Operator-Token": "test-token"}


@pytest.fixture()
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def sample_image() -> str:
    settings.images_dir.mkdir(parents=True, exist_ok=True)
    img_path = settings.images_dir / "test_disk.img"
    manifest = build_synthetic_file(img_path, 2 * 1024 * 1024)
    manifest_path = img_path.with_suffix(img_path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest))
    return img_path.name
