"""Application configuration, loaded from environment variables / .env."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

FROZEN = getattr(sys, "frozen", False)

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Bundled, read-only resources (the built frontend). This is the backend/
# source directory when running from source, or PyInstaller's onefile
# extraction directory when packaged into an .exe.
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", BACKEND_DIR))
FRONTEND_DIST_DIR = BUNDLE_DIR / "frontend_dist"

# Writable, per-user data. A packaged .exe's own folder (e.g. under
# Program Files, or a temp extraction dir for onefile builds) may not be
# writable and isn't a stable location, so frozen builds keep their data
# under the user's profile instead.
if FROZEN:
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "ZeroTrace"
else:
    DATA_DIR = BACKEND_DIR / "instance"

INSTANCE_DIR = DATA_DIR


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ZEROTRACE_", env_file=".env", extra="ignore")

    app_name: str = "ZeroTrace"
    app_version: str = "1.0.0"

    # SQLite fallback by default; set ZEROTRACE_DATABASE_URL to a MySQL URL
    # (e.g. mysql+pymysql://user:pass@host/db) to use MySQL instead.
    database_url: str = f"sqlite:///{(INSTANCE_DIR / 'zerotrace.db').as_posix()}"

    # Directory operators are allowed to load disk images from. Any image
    # path outside this directory is rejected to prevent path traversal /
    # arbitrary filesystem access.
    images_dir: Path = INSTANCE_DIR / "images"
    workspace_dir: Path = INSTANCE_DIR / "workspace"
    certificates_dir: Path = INSTANCE_DIR / "certificates"
    keys_dir: Path = INSTANCE_DIR / "keys"

    # Operator API keys. Format: "operator_id:token,operator_id2:token2".
    # Defaults to a single demo operator so the app is usable out of the box;
    # override in production via env var / .env.
    operator_keys: str = "demo-operator:demo-token"

    def operator_map(self) -> dict[str, str]:
        pairs = [p.strip() for p in self.operator_keys.split(",") if p.strip()]
        result: dict[str, str] = {}
        for pair in pairs:
            if ":" not in pair:
                continue
            operator_id, token = pair.split(":", 1)
            result[token] = operator_id
        return result


settings = Settings()

for d in (INSTANCE_DIR, settings.images_dir, settings.workspace_dir,
          settings.certificates_dir, settings.keys_dir):
    d.mkdir(parents=True, exist_ok=True)
