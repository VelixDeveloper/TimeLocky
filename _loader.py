# -*- coding: utf-8 -*-
"""
TimeLocky encrypted module importer.
Installed by run.py before any project imports.
Decrypts .pyc.enc files in-memory — nothing is written to disk.
"""
import importlib.abc
import importlib.util
import marshal
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

# Python 3.8+ .pyc header layout:
#   magic(4) | flags(4) | mtime-or-hash(4) | source-size-or-hash2(4) = 16 bytes
# This constant matches importlib._bootstrap_external.MAGIC_NUMBER usage.
_PYC_HEADER = 16


def _load_code(pyc_bytes: bytes, name: str):
    """Strip .pyc header, unmarshal and return a code object."""
    if len(pyc_bytes) < _PYC_HEADER + 4:
        raise ImportError(
            f"Encrypted module '{name}' is too small — file may be corrupted."
        )
    try:
        return marshal.loads(pyc_bytes[_PYC_HEADER:])
    except Exception as exc:
        raise ImportError(
            f"Failed to unmarshal '{name}': {exc}\n"
            "The file may be corrupted or was compiled with a different Python version.\n"
            f"Your Python: {sys.version}"
        ) from exc


class EncryptedImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):

    def __init__(self, key: bytes, encrypted_dir: str):
        self._f    = Fernet(key)
        self._base = Path(encrypted_dir)

    # ── locate encrypted file ─────────────────────────────────────────────────

    def _enc_path(self, fullname: str):
        parts = fullname.split(".")
        rel   = Path(*parts)
        # Package: gui → encrypted/gui/__init__.pyc.enc
        pkg = self._base / rel / "__init__.pyc.enc"
        if pkg.exists():
            return pkg, True
        # Module: gui.app → encrypted/gui/app.pyc.enc
        mod = self._base / rel.with_suffix(".pyc.enc")
        if mod.exists():
            return mod, False
        return None, False

    # ── MetaPathFinder ────────────────────────────────────────────────────────

    def find_spec(self, fullname, path, target=None):
        enc, is_pkg = self._enc_path(fullname)
        if enc is None:
            return None
        search = [str(enc.parent)] if is_pkg else None
        return importlib.util.spec_from_file_location(
            fullname, str(enc), loader=self,
            submodule_search_locations=search,
        )

    # ── Loader ────────────────────────────────────────────────────────────────

    def create_module(self, spec):
        return None   # use Python's default module object

    def exec_module(self, module):
        name     = module.__spec__.name
        enc_path = Path(module.__spec__.origin)

        # 1. Read encrypted file
        try:
            raw = enc_path.read_bytes()
        except OSError as exc:
            raise ImportError(
                f"Cannot read encrypted module '{name}': {exc}"
            ) from exc

        # 2. Decrypt
        try:
            pyc_bytes = self._f.decrypt(raw)
        except InvalidToken:
            raise ImportError(
                f"Decryption failed for '{name}'.\n"
                "Possible causes:\n"
                "  - The key from the server does not match the encrypted files.\n"
                "  - Re-run  protect.py  and re-distribute the protected/ folder.\n"
                "  - In DEV mode, make sure .master_key is beside run.py."
            )
        except Exception as exc:
            raise ImportError(f"Unexpected decryption error for '{name}': {exc}") from exc

        # 3. Unmarshal code object (strips 16-byte .pyc header)
        code = _load_code(pyc_bytes, name)

        # 4. Execute into module namespace
        try:
            exec(code, module.__dict__)
        except Exception as exc:
            # Re-raise so tracebacks show the real module name, not _loader
            raise type(exc)(
                f"Error while initialising module '{name}': {exc}"
            ) from exc
