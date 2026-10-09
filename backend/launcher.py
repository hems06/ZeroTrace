"""Desktop launcher entrypoint for the packaged ZeroTrace.exe.

Starts the FastAPI app with an embedded uvicorn server and opens the user's
default browser once it is ready to accept connections. This is the single
entrypoint PyInstaller packages into ZeroTrace.exe -- running it is the
entire "installation": it needs no separate Python, Node, or server setup,
and stores its data under %LOCALAPPDATA%\\ZeroTrace (see app/config.py).
"""
from __future__ import annotations

import socket
import threading
import time
import webbrowser

import uvicorn

from app.main import app


def _find_free_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _open_browser_when_ready(port: int, url: str) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.3)
    webbrowser.open(url)


def main() -> None:
    import platform
    if platform.system() == "Windows":
        import ctypes
        import sys
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
            
        if not is_admin:
            print("Requesting Administrator privileges for physical device operations...")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)

    port = _find_free_port(8000)
    url = f"http://127.0.0.1:{port}"

    print("=" * 60)
    print("  ZeroTrace -- Secure Data Wiping for IT Asset Recycling")
    print("=" * 60)
    print(f"  Starting local server at {url}")
    print("  Your browser will open automatically.")
    print("  Close this window (or press Ctrl+C) to stop ZeroTrace.")
    print("=" * 60)

    threading.Thread(target=_open_browser_when_ready, args=(port, url), daemon=True).start()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info")
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()
