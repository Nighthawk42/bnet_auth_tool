"""Filesystem helpers: atomic, permission-hardened writes.

Authenticator material is sensitive, so written files are created with owner-
only permissions (``0o600``) where the platform supports it, and writes are
atomic (temp file + ``os.replace``) so a crash mid-write cannot truncate an
existing vault.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

# Owner read/write only.
SECRET_FILE_MODE = 0o600


def _harden(path: Path) -> None:
    """Best-effort chmod to owner-only; a no-op on platforms without POSIX perms."""
    # Windows / restricted filesystems: ACLs differ; nothing portable to do.
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, SECRET_FILE_MODE)


def atomic_write_bytes(path: Path, data: bytes, *, secret: bool = True) -> None:
    """Atomically write ``data`` to ``path``.

    Writes to a temp file in the same directory, fsyncs it, hardens its
    permissions, then atomically replaces the destination.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if secret:
            _harden(tmp_path)
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def atomic_write_text(path: Path, text: str, *, secret: bool = True) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), secret=secret)
