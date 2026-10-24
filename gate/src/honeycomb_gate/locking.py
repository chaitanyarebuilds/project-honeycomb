"""Small cross-process file lock (POSIX ``flock``, Windows ``msvcrt``), no dependency."""

import json
import os
import sys
import tempfile
from pathlib import Path
from types import TracebackType
from typing import IO, Any


class StateCorruptError(RuntimeError):
    """A state file exists but cannot be read. The message names the file and what to do."""


def read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    """Read a JSON object from ``path``, or ``default`` if the file doesn't exist."""
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
    except (ValueError, OSError) as exc:  # includes JSONDecodeError and UnicodeDecodeError
        raise StateCorruptError(
            f"{path} is damaged ({type(exc).__name__}). Restore it from a backup, or move it "
            "aside (keep it as evidence) if you want to start this part of the state fresh."
        ) from exc
    return data


def write_json_atomic(path: Path, data: object, **dump_kwargs: Any) -> None:
    """Replace ``path`` with ``data`` as JSON: private temp file, fsync, then atomic rename."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, **dump_kwargs)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class LockedError(RuntimeError):
    """Another process holds the lock."""


class FileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh: IO[bytes] | None = None

    def acquire(self, *, blocking: bool = True) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fh = self.path.open("ab")
        try:
            if sys.platform == "win32":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except OSError as exc:
            fh.close()
            raise LockedError(f"{self.path} is locked by another process") from exc
        self._fh = fh

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt

                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()
