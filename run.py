#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TimeLocky — Secure Launcher
=============================
1. Reads API credentials from dev.env (place beside this file).
2. Computes the hardware ID (HWID) of this machine.
3. Verifies registration with your backend — only registered HWIDs proceed.
4. Downloads the Fernet decryption key for this session.
5. Installs an in-memory encrypted importer and starts the app.

DEV / LOCAL TESTING
-------------------
To test without a backend, set in dev.env:
    DEV_BYPASS_REGISTRATION=true

Then copy protected/.master_key to this directory.
The key is loaded directly from .master_key instead of the server.
NEVER ship a build with DEV_BYPASS_REGISTRATION=true.
"""

import hashlib
import os
import platform
import subprocess
import sys
import uuid
from pathlib import Path

# ── Root dirs — set BEFORE any project imports ────────────────────────────────
_HERE = Path(__file__).resolve().parent
_ENC  = _HERE / "encrypted"
_DATA = _HERE / "data"

# Let paths.py know where user-writable files live
os.environ.setdefault("TL_APP_ROOT", str(_DATA))
# Let dev_config.py find dev.env beside run.py
os.environ.setdefault("TL_EXE_DIR",  str(_HERE))

# ── dev.env reader — pure stdlib, no project imports yet ─────────────────────

def _read_env(path: Path) -> dict:
    cfg: dict = {}
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            cfg[k.strip().upper()] = v.strip()
    return cfg

_cfg = _read_env(_HERE / "dev.env")
_API = _cfg.get("API_BASE_URL", "").rstrip("/")
_SEC = _cfg.get("API_SECRET",  "")
_DEV_BYPASS = _cfg.get("DEV_BYPASS_REGISTRATION", "false").lower() in (
    "true", "1", "yes", "on"
)

# ── HWID (same algorithm as gui/utils/hwid.py) ────────────────────────────────

def _get_hwid() -> str:
    bits = [platform.node(), platform.machine(), str(uuid.getnode())]
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode(errors="ignore")
            for line in out.splitlines():
                v = line.strip()
                if v and v.upper() != "UUID":
                    bits.append(v)
                    break
        except Exception:
            pass
    return hashlib.sha512("|".join(bits).encode()).hexdigest()

# ── Key acquisition ───────────────────────────────────────────────────────────

def _key_from_server(hwid: str) -> bytes:
    """Verify HWID with backend and retrieve the Fernet decryption key."""
    try:
        import requests
    except ImportError:
        sys.exit(
            "\nERROR: missing dependency.\n"
            "Run:  pip install requests cryptography\n"
        )

    if not _API:
        sys.exit(
            "\nERROR: API_BASE_URL is not set in dev.env.\n"
            "Add:  API_BASE_URL=http://your-server/backend\n"
        )
    if not _SEC or _SEC == "change-me-before-deploying":
        sys.exit("\nERROR: API_SECRET is not set in dev.env.\n")

    print(f"  Verifying HWID with {_API} …")
    try:
        resp = requests.post(
            f"{_API}/getkey.php",
            json={"secret": _SEC, "hwid": hwid},
            timeout=15,
        )
        resp.raise_for_status()
    except Exception as exc:
        sys.exit(f"\nERROR: Cannot reach auth server — {exc}\n")

    data = resp.json()
    if "error" in data:
        code   = data["error"]
        reason = data.get("reason", "")
        if code == "unauthorized":
            if reason == "not_registered":
                hwid_short = hwid[:16] + "…"
                sys.exit(
                    "\nAccess denied — this machine is not registered.\n"
                    "Contact your admin via Telegram to register your HWID.\n"
                    f"Your HWID: {hwid}\n"
                )
            sys.exit(f"\nAccess denied ({reason}). Contact your admin.\n")
        if code == "key_not_configured":
            sys.exit(
                "\nERROR: The server has no master key stored.\n"
                "Run:  python protect.py  (without --local-only) to upload it.\n"
            )
        sys.exit(f"\nAuth error from server: {code}\n")

    raw = data.get("key", "")
    if not raw:
        sys.exit("\nERROR: Server returned an empty key.\n")
    return raw.encode()


def _key_from_file() -> bytes:
    """DEV MODE: load key directly from .master_key beside run.py."""
    key_file = _HERE / ".master_key"
    if not key_file.exists():
        sys.exit(
            "\nDEV MODE: .master_key not found beside run.py.\n"
            "Copy protected/.master_key here, or run protect.py first.\n"
        )
    print("  [DEV] Loading key from .master_key (bypass mode).")
    return key_file.read_bytes()


def _get_key(hwid: str) -> bytes:
    if _DEV_BYPASS:
        return _key_from_file()
    return _key_from_server(hwid)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if _DEV_BYPASS:
        print("\nTimeLocky — Starting… [DEV BYPASS MODE]")
    else:
        print("\nTimeLocky — Starting…")

    hwid = _get_hwid()
    key  = _get_key(hwid)

    if not _DEV_BYPASS:
        print("  Registration verified.\n")

    # Validate key format before installing importer
    try:
        from cryptography.fernet import Fernet
        Fernet(key)   # will raise ValueError if key is malformed
    except Exception as exc:
        sys.exit(
            f"\nERROR: The key received is not a valid Fernet key: {exc}\n"
            "This usually means the key in the database is corrupted.\n"
            "Re-run protect.py to regenerate and re-upload the key.\n"
        )

    # Create writable dirs before any project module touches the filesystem
    os.makedirs(str(_DATA),          exist_ok=True)
    os.makedirs(str(_HERE / "logs"), exist_ok=True)

    # Install encrypted importer BEFORE any project imports
    sys.path.insert(0, str(_HERE))
    from _loader import EncryptedImporter
    sys.meta_path.insert(0, EncryptedImporter(key, str(_ENC)))

    # encrypted/ must also be on path for absolute imports inside modules
    sys.path.insert(0, str(_ENC))

    # Hand off to the real application
    from gui.app import run
    run()


if __name__ == "__main__":
    main()
