"""Honeytokens: fake credentials that only a snooping or hijacked agent would touch (F6).

Token formats are written from scratch from the general shape of common credentials, each
with a random id embedded so a sighting can be traced to one planted token. Values are
generated at deploy time and stored under the state directory only; they must never be
committed (some look like real keys and would trip secret scanners).
"""

import base64
import re
import secrets
import string
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from honeycomb_gate.locking import FileLock, StateCorruptError, read_json, write_json_atomic
from honeycomb_gate.walk import strings_of

KINDS = ("api-key", "db-url", "webhook-url", "password")
_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
_BODY = string.ascii_letters + string.digits
_WORDS = ["Harbor", "Maple", "Copper", "Falcon", "Meadow", "Quartz", "Lantern", "Cedar"]
_ENV_NAMES = {
    "api-key": "PAYMENTS_API_KEY",
    "db-url": "DATABASE_URL",
    "webhook-url": "SLACK_WEBHOOK_URL",
    "password": "ADMIN_PASSWORD",
}
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u00ad\ufeff]")
_B64_RUN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")


def _rand(n: int) -> str:
    return "".join(secrets.choice(_BODY) for _ in range(n))


def new_token_id() -> str:
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(12))


def generate_value(kind: str, token_id: str) -> str:
    if kind == "api-key":
        return f"sk_live_{token_id}{_rand(24)}"
    if kind == "db-url":
        return f"postgresql://svc_{token_id}:{_rand(20)}@db.internal.example.test:5432/appdb"
    if kind == "webhook-url":
        return f"https://hooks.example.test/services/T{token_id}/{_rand(24)}"
    if kind == "password":
        return f"{secrets.choice(_WORDS)}{secrets.choice(_WORDS)}-{token_id}"
    raise ValueError(f"unknown kind {kind!r}; choose one of {', '.join(KINDS)}")


@dataclass
class Token:
    id: str
    kind: str
    value: str
    created: str
    placed: list[str] = field(default_factory=list)
    revoked: bool = False


@dataclass
class Sighting:
    token_id: str
    kind: str
    placed: list[str]


def _unescaped(text: str) -> Iterator[str]:
    """The text, then the text with percent-escapes undone, up to four layers deep."""
    yield text
    for _ in range(4):
        decoded = unquote(text)
        if decoded == text:
            return
        text = decoded
        yield text


class TokenRegistry:
    """Registered honeytokens, shared between the CLI and the running gate."""

    def __init__(self, path: Path, *, read_only: bool = False) -> None:
        """``read_only`` is for a reader that can't write next to the file (a read-only mount).

        Writers replace the file atomically, so a reader never sees half of it and needs no lock.
        """
        self.path = path
        self._read_only = read_only
        self._lock = FileLock(path.with_name(path.name + ".lock"))
        self._cache: list[Token] = []
        self._mtime: int | None = None

    def _read(self) -> list[Token]:
        try:
            return [Token(id=i, **v) for i, v in read_json(self.path, {}).items()]
        except TypeError as exc:  # a record with the wrong fields
            raise StateCorruptError(f"{self.path} has a damaged record ({exc}).") from exc

    def _write(self, tokens: list[Token]) -> None:
        body = {t.id: {k: v for k, v in t.__dict__.items() if k != "id"} for t in tokens}
        write_json_atomic(self.path, body, indent=2)

    def tokens(self) -> list[Token]:
        if not self.path.exists():
            return []
        mtime = self.path.stat().st_mtime_ns
        if mtime != self._mtime:
            if self._read_only:
                self._cache = self._read()
            else:
                with self._lock:
                    self._cache = self._read()
            self._mtime = mtime
        return self._cache

    def create(self, kind: str, placed: list[str] | None = None) -> Token:
        token_id = new_token_id()
        token = Token(
            id=token_id,
            kind=kind,
            value=generate_value(kind, token_id),
            created=datetime.now(UTC).isoformat(timespec="seconds"),
            placed=placed or [],
        )
        with self._lock:
            tokens = self._read()
            tokens.append(token)
            self._write(tokens)
        self._mtime = None
        return token

    def add_placement(self, token_id: str, where: str) -> None:
        with self._lock:
            tokens = self._read()
            for t in tokens:
                if t.id == token_id:
                    t.placed.append(where)
            self._write(tokens)
        self._mtime = None

    def revoke(self, token_id: str) -> bool:
        with self._lock:
            tokens = self._read()
            hit = [t for t in tokens if t.id == token_id]
            for t in hit:
                t.revoked = True
            self._write(tokens)
        self._mtime = None
        return bool(hit)

    def find(self, payload: Any) -> list[Sighting]:
        """Registered tokens that appear anywhere in ``payload``.

        Matches the value or the embedded id, ignoring case and invisible characters, across
        every string in the payload (also when a value is split over several fields) and
        inside base64 text. Other encodings (rot13, hex, ad-hoc ciphers) are not matched.
        """
        active = [t for t in self.tokens() if not t.revoked]
        if not active:
            return []
        strings = strings_of(payload, numbers=True)
        values = strings_of(payload, keys=False, numbers=True)
        # Keys and values together, values only, and values run together (a token split over
        # several fields or list items).
        views = ["\n".join(strings), "\n".join(values), "".join(values)]
        texts: list[str] = []
        for view in views:
            for seen in _unescaped(view):
                texts.append(_INVISIBLE.sub("", seen).lower())
                texts.extend(_decoded_runs(seen))
        return [
            Sighting(t.id, t.kind, t.placed)
            for t in active
            if any(t.id in x or t.value.lower() in x for x in texts)
        ]

    def mask(self, payload: Any) -> Any:
        """Copy of ``payload`` with token values replaced by a label, so logs never hold them."""
        tokens = [t for t in self.tokens() if not t.revoked]
        if not tokens:
            return payload
        labels: dict[str, str] = {}
        for t in tokens:
            labels[t.value] = labels[t.id] = f"[HONEYTOKEN:{t.id}]"
        # One pass, longest match first, so a value is never half-replaced by its own id.
        pattern = re.compile(
            "|".join(re.escape(k) for k in sorted(labels, key=len, reverse=True)), re.IGNORECASE
        )
        lowered = {k.lower(): v for k, v in labels.items()}

        def walk(v: Any) -> Any:
            if isinstance(v, str):
                return pattern.sub(lambda m: lowered[m.group(0).lower()], v)
            if isinstance(v, dict):
                return {k: walk(x) for k, x in v.items()}
            if isinstance(v, list | tuple):
                return [walk(x) for x in v]
            return v

        return walk(payload)


def _decoded_runs(original: str) -> list[str]:
    """Readable text hidden inside base64-looking runs, lower-cased for matching."""
    out: list[str] = []
    for run in _B64_RUN.findall(original)[:200]:
        body = run.rstrip("=")
        padded = body + "=" * (-len(body) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                out.append(_INVISIBLE.sub("", decoder(padded).decode("utf-8", "ignore")).lower())
            except (ValueError, TypeError):
                continue
    return out


class PlacementError(ValueError):
    pass


def _inside_git_repo(path: Path) -> bool:
    return any((p / ".git").exists() for p in [path.resolve(), *path.resolve().parents])


def place(token: Token, target: Path, *, allow_in_repo: bool = False) -> Path:
    """Write the token into a file in the agent's workspace, as a plausible leftover entry.

    ``target`` may be a file (a line is appended) or a directory (``.env.old`` is created).
    Refuses to write inside a git work tree unless told otherwise: tokens must not be committed.
    """
    dest = (target / ".env.old" if target.is_dir() else target).resolve()  # follow symlinks
    if _inside_git_repo(dest.parent) and not allow_in_repo:
        raise PlacementError(
            f"{dest} is inside a git repository. Honeytokens must never be committed. "
            "Place it in a workspace outside the repo, or pass --allow-in-repo and make sure "
            "the file is ignored."
        )
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("a", encoding="utf-8") as f:
            f.write(f"{_ENV_NAMES[token.kind]}={token.value}\n")
    except OSError as exc:
        raise PlacementError(
            f"could not write to {dest}: {exc.strerror or type(exc).__name__}"
        ) from exc
    return dest
