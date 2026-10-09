# ZeroTrace

**Secure Data Wiping for Trustworthy IT Asset Recycling**

ZeroTrace is a prototype for sanitizing storage devices before recycling, reuse,
resale, or disposal, with independent verification and a tamper-evident,
digitally signed certificate of sanitization.

This build focuses on making the **image-based testing workflow** fully real and
safe to run without any physical hardware, while being explicit — in the UI, the
API, and the certificate — about what is simulated, what is genuinely executed
and verified, and what is intentionally not implemented for safety reasons.

## Windows: run it as a single .exe (no setup)

A prebuilt-style portable executable is available via the build script below —
`ZeroTrace.exe` is a single file that needs no separate install step:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
```

This produces `backend\dist\ZeroTrace.exe`. Double-click it (or run it from a
terminal): it starts a local server, opens your default browser to the
dashboard automatically, and stores all its data under
`%LOCALAPPDATA%\ZeroTrace\` (database, demo images, certificates, signing
key) — nothing is written next to the exe itself, and nothing requires admin
rights. A sample disk image with synthetic marker data is generated
automatically the first time it runs, so the full image-based demo works
immediately. Close the console window (or Ctrl+C) to stop it.

This is genuinely one file: no installer, no Python, no Node, no separate
server process to start. See `scripts/build_exe.ps1` for exactly what it does
(build the frontend, copy it into `backend/frontend_dist`, then run
PyInstaller `--onefile` against `backend/launcher.py`). Rebuild it any time
after changing the frontend or backend by re-running the script.

## Architecture

```
backend/   FastAPI app (Python) — API, sanitization engine, verification
           engine, certificate generator, hash-linked audit ledger
frontend/  React + TypeScript + Tailwind dashboard
```

```
app/
  devices/        physical device discovery (read-only) + image target
                  discovery/validation + synthetic dataset generation
  sanitization/   policy definitions, overwrite primitive, engine
                  orchestrator (demo / image / physical-guarded)
  verification/   post-operation verification engine
  audit/          hash-linked append-only audit ledger
  certificates/   RSA signing + PDF generation + certificate verification
  routes/         REST API (FastAPI routers)
```

Database is SQLite by default (`backend/instance/zerotrace.db`); set
`ZEROTRACE_DATABASE_URL` to a MySQL URL (e.g.
`mysql+pymysql://user:pass@host/db`) to use MySQL instead — no code changes
needed, SQLAlchemy handles both.

## Setup

Requires Python 3.10+ and Node 18+.

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate        # Windows; use `source .venv/bin/activate` on Linux/macOS
pip install -r requirements.txt

cd ../frontend
npm install
```

## Running

**Backend** (from `backend/`, with the venv active):

```bash
uvicorn app.main:app --reload --port 8000
```

On first run this creates `backend/instance/` (SQLite DB, images directory,
workspace, certificates output, and an RSA signing keypair — never commit
`instance/keys/`).

**Frontend** (from `frontend/`):

```bash
npm run dev
```

Open `http://localhost:5173`. The Vite dev server proxies `/api/*` to
`http://127.0.0.1:8000`.

(The backend also serves the built frontend directly from
`backend/frontend_dist/` on its own port if that folder exists — e.g. after
running `npm run build` and copying `frontend/dist` there, or after running
`scripts/build_exe.ps1`. That single-port mode is what `ZeroTrace.exe` uses;
see below.)

Default operator token for the demo: `demo-token` (set via
`ZEROTRACE_OPERATOR_KEYS=demo-operator:demo-token`, see `app/config.py`). The
frontend sets this automatically in `localStorage` on first load; change it in
the top-right "Operator token" field if you configure different credentials.

## Running tests

```bash
cd backend
.venv/Scripts/python -m pytest tests/ -v
```

38 tests, all passing: image discovery/validation (including path-traversal
and unsupported-format rejection), image-based sanitization + verification,
original-image integrity preservation, failed/inconclusive verification
paths, certificate generation + tamper detection, audit-chain tamper
detection, unauthorized/invalid-input rejection, OS-disk protection, and full
API integration.

Tests use an isolated `backend/instance_test/` directory and a disposable
SQLite file — they never touch your real `instance/` data and never wipe a
real device.

## Demonstration walkthrough (no USB required)

1. Generate a sample disk image with synthetic marker data (already done once
   automatically, but you can regenerate it):

   ```bash
   cd backend
   .venv/Scripts/python demo_data/generate_sample_image.py
   ```

   This writes `backend/instance/images/sample_disk.img` (an 8 MB raw image
   file standing in for an extracted storage-device image) plus a
   `.manifest.json` sidecar recording 5 synthetic "sensitive record" markers
   at known offsets. No real personal data is used.

2. Start the backend and frontend (see above) and open
   `http://localhost:5173`.

3. **Dashboard** — shows live counts (all zero on a fresh database).

4. **Sanitize tab** → choose **"Image-based test"** → select `sample_disk.img`
   (its size, media-type label, and marker count are shown) → choose a
   sanitization policy (e.g. *Clear – Single-pass zero overwrite*) → **Execute
   operation**.

   What happens, in order: the original image is hashed and never opened for
   writing; a disposable working copy is made in `instance/workspace/`; the
   overwrite pass(es) run against that copy only; the verification engine
   checks that all 5 markers are gone from the copy, that its hash changed,
   and that the *original* image's hash still matches what was recorded at
   discovery time; the working copy is then deleted. The UI shows
   `completed` / `verified` with the evidence (marker counts, hashes,
   `original_untouched: true`) and the method's documented limitations.

5. Click **Generate certificate** — a PDF certificate is created from the
   recorded operation data, RSA-signed, and immediately verified in place
   ("Integrity verified"). Download it with **Download PDF**.

6. **Certificates tab** — lists all issued certificates; "Check" re-verifies
   signature + hash + fingerprint independently.

7. **Audit Log tab** — shows every lifecycle event (target discovered →
   selected → operator confirmation → sanitization started/completed →
   verification performed → certificate issued) as a hash-linked chain, with
   a live "chain intact" check.

You can repeat the same flow with **Demonstration mode** (no image needed —
generates and wipes a synthetic dataset in an isolated temp workspace) or
inspect **Physical device** discovery, which lists real disks on your machine
read-only and will refuse to let you select the one hosting the OS.

## Supported vs. simulated vs. not implemented

| Capability | Status |
|---|---|
| OS storage device discovery (Windows/Linux, read-only) | **Implemented** |
| Image-based target discovery, validation, path-traversal protection | **Implemented** |
| Image-based sanitization on an isolated working copy, original preserved | **Implemented** |
| Demonstration mode on synthetic data | **Implemented** |
| Verification engine (hashes, marker scan, original-integrity check) | **Implemented**, with documented scale limits (full-content scan only below 256 MB; real devices need representative sampling, not a full scan) |
| Hash-linked tamper-evident audit log | **Implemented** (chain-replay detection only — see limitation below) |
| PDF certificate generation | **Implemented** |
| RSA digital signature on certificates (not just a hash) | **Implemented** (RSA-3072 PSS/SHA-256; private key in `instance/keys/`, gitignored) |
| Certificate integrity/authenticity verification endpoint | **Implemented** |
| Physical-device pre-flight guards (system-disk block, mount check, explicit confirmation phrase, operator auth) | **Implemented** |
| Physical-device **destructive** execution (ATA Secure Erase / NVMe Sanitize) | **Not implemented.** Disabled by default (`ZEROTRACE_ALLOW_PHYSICAL_EXECUTION=false`); even when enabled, the engine reports `blocked_not_implemented` rather than fabricate a wipe. Implementing this safely requires a signed, least-privilege, platform-specific helper outside this prototype's scope. |
| "Purge" via software overwrite | **Emulated, clearly labeled as such** — overwrite does not guarantee Purge-level sanitization on flash/SSD media; the certificate and UI state this explicitly. |
| "Destroy" | **Documentation only** — ZeroTrace never claims to physically destroy a device. |
| MySQL support | **Implemented** via `ZEROTRACE_DATABASE_URL`; SQLite is the default for local/dev use. |

## Safety and verification limitations (stated, not hidden)

- **Verification scope**: marker presence is checked via a hashed
  sliding-window comparison around recorded offsets, not a full plaintext
  signature scan, and full-content scanning is capped at demo/test scale.
  Real multi-GB/TB devices need representative sampling per NIST SP 800-88
  guidance, not a full scan.
- **Audit chain**: hash-linking detects tampering via chain replay (if any
  past event is altered or deleted, every entry after it fails to verify).
  It does **not** prevent an attacker with full database write access from
  regenerating a consistent chain from scratch — true tamper-*prevention*
  would need external anchoring (WORM storage, periodic notarization, a
  separate signing authority), which is out of scope here.
- **Overwrite-based Purge** is an emulation, not a substitute for a device's
  native cryptographic erase / Secure Erase / Sanitize command, and is
  labeled as such everywhere it's reported (API, UI, certificate).
- **No destructive action ever runs on startup** or without an explicit
  operator-confirmed request through the API.

## REST API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness check |
| GET | `/api/devices` | physical devices (read-only) + image targets |
| GET | `/api/methods` | available sanitization methods/policies |
| GET | `/api/operations` | list operations |
| POST | `/api/operations` | create + execute an operation (operator auth required) |
| GET | `/api/operations/{id}` | operation detail |
| POST | `/api/operations/{id}/verify` | re-check stored evidence consistency (operator auth required) |
| GET | `/api/certificates` | list certificates |
| GET | `/api/certificates/{id}` | certificate metadata |
| GET | `/api/certificates/{id}/download` | download the PDF |
| POST | `/api/certificates/{id}/verify` | verify signature/hash/fingerprint |
| POST | `/api/certificates/for-operation/{id}` | issue a certificate for a finished operation (operator auth required) |
| GET | `/api/audit` | full audit event list |
| GET | `/api/audit/verify-chain` | replay the hash chain, report tampering |
| GET | `/api/dashboard/summary` | aggregate counts + recent activity |

Sensitive endpoints (creating/re-verifying operations, issuing certificates)
require an `X-Operator-Token` header, resolved to an operator id via
`ZEROTRACE_OPERATOR_KEYS` in `app/config.py`.
