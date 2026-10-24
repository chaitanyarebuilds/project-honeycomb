"""Run identity (F7, ADR-0002): signed tokens an agent presents, and a registry to revoke them.

A token is ``hc1.<payload>.<signature>``. The payload is JSON (run id, agent id, scopes, issued
and expiry times, key id) and the signature is HMAC-SHA256 over it. Only the gate holds the key,
so only the gate can check a token. A valid signature is not enough: the run must also still be
active in the registry, which is how a trip or an operator revokes it.
"""

import base64
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from honeycomb_gate.events import new_run_id
from honeycomb_gate.locking import FileLock, read_json, write_json_atomic

PREFIX = "hc1"
MAX_TTL_S = 900  # the spec says 15 minutes or less
KEY_ENV = "HONEYCOMB_RUN_KEY"
AGENT_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


class TokenError(Exception):
    """A token that must not be accepted. The message is for the log, never for the caller."""


@dataclass(frozen=True)
class Claims:
    run_id: str
    agent_id: str
    scopes: tuple[str, ...]
    issued: int
    expires: int
    kid: str


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    """Strict: only the canonical spelling decodes, so one token has one string."""
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if _b64(raw) != text:
        raise ValueError("not canonical base64")
    return raw


class KeyRing:
    """Signing keys: the ``HONEYCOMB_RUN_KEY`` variable, or a private file in the state folder.

    Rotating adds a new current key and keeps the old ones, so tokens signed a moment ago still
    verify. ``prune`` drops keys that no live token can have been signed with.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = FileLock(path.with_name(path.name + ".lock"))

    def _load(self) -> dict[str, Any]:
        return read_json(self.path, {})

    def _save(self, data: dict[str, Any]) -> None:
        write_json_atomic(self.path, data, indent=2)
        os.chmod(self.path, 0o600)

    def current(self) -> tuple[str, bytes]:
        env = os.environ.get(KEY_ENV, "")
        if env:
            if len(env) < 32:
                raise TokenError(f"{KEY_ENV} must be at least 32 characters")
            return "env", env.encode()
        with self._lock:
            data = self._load()
            if not data.get("current"):
                data = self._new_key(data)
                self._save(data)
        return data["current"], bytes.fromhex(data["keys"][data["current"]]["key"])

    def _new_key(self, data: dict[str, Any]) -> dict[str, Any]:
        # Random after the first, so pruning old keys can never make a new id repeat a live one.
        kid = f"k{secrets.token_hex(3)}" if data.get("keys") else "k1"
        keys = {
            **data.get("keys", {}),
            kid: {"key": secrets.token_hex(32), "created": int(time.time())},
        }
        return {"current": kid, "keys": keys}

    def key(self, kid: str) -> bytes | None:
        if kid == "env":
            env = os.environ.get(KEY_ENV, "")
            return env.encode() if len(env) >= 32 else None
        entry = self._load().get("keys", {}).get(kid)
        return bytes.fromhex(entry["key"]) if entry else None

    def rotate(self) -> str:
        with self._lock:
            data = self._new_key(self._load())
            self._save(data)
        return str(data["current"])

    def prune(self) -> list[str]:
        """Forget keys older than the longest a token can live, except the current one."""
        with self._lock:
            data = self._load()
            cutoff = time.time() - 2 * MAX_TTL_S
            gone = [k for k, v in data.get("keys", {}).items()
                    if k != data.get("current") and v["created"] < cutoff]  # fmt: skip
            for k in gone:
                del data["keys"][k]
            if gone:
                self._save(data)
        return gone


class Identities:
    """Who holds a live identity. The gate reads this on every request, the CLI changes it."""

    def __init__(self, path: Path, keys: KeyRing) -> None:
        self.path = path
        self.keys = keys
        self._lock = FileLock(path.with_name(path.name + ".lock"))

    def _read(self) -> dict[str, dict[str, Any]]:
        return read_json(self.path, {})

    def get(self, run_id: str) -> dict[str, Any] | None:
        return self._read().get(run_id)

    def all(self) -> dict[str, dict[str, Any]]:
        return self._read()

    def _token(self, run_id: str, agent_id: str, scopes: list[str], now: int, ttl: int) -> str:
        kid, key = self.keys.current()
        claims = {"run": run_id, "agent": agent_id, "scopes": scopes,
                  "iat": now, "exp": now + ttl, "kid": kid}  # fmt: skip
        body = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
        sig = _b64(hmac.new(key, f"{PREFIX}.{body}".encode(), sha256).digest())
        return f"{PREFIX}.{body}.{sig}"

    def issue(
        self,
        agent_id: str,
        scopes: list[str],
        ttl_s: int = MAX_TTL_S,
        resumed_from: str | None = None,
    ) -> tuple[str, str]:
        """Mint a new run and its first token. Returns ``(run_id, token)``."""
        if not AGENT_ID.fullmatch(agent_id):
            raise TokenError("an agent id is 1 to 64 letters, digits, dots, dashes or underscores")
        ttl = self._ttl(ttl_s)
        now = int(time.time())
        run_id = new_run_id()
        with self._lock:
            data = self._read()
            data[run_id] = {"agent": agent_id, "scopes": scopes, "status": "active",
                            "issued": now, "expires": now + ttl,
                            "resumed_from": resumed_from}  # fmt: skip
            write_json_atomic(self.path, data, indent=2)
        return run_id, self._token(run_id, agent_id, scopes, now, ttl)

    def renew(self, run_id: str, ttl_s: int = MAX_TTL_S, scopes: list[str] | None = None) -> str:
        """A fresh token for a run that is still active. Revoked runs stay revoked.

        ``scopes``, if given, replaces the stored ones, so a narrowed policy reaches the run.
        """
        ttl = self._ttl(ttl_s)
        now = int(time.time())
        with self._lock:
            data = self._read()
            entry = data.get(run_id)
            if entry is None or entry["status"] != "active":
                raise TokenError("that run has no live identity to renew")
            entry["expires"] = now + ttl
            if scopes is not None:
                entry["scopes"] = scopes
            write_json_atomic(self.path, data, indent=2)
        return self._token(run_id, entry["agent"], entry["scopes"], now, ttl)

    def revoke(self, run_id: str, reason: str) -> bool:
        with self._lock:
            data = self._read()
            entry = data.get(run_id)
            if entry is None or entry["status"] != "active":
                return False
            entry.update(status="revoked", reason=reason, revoked_at=int(time.time()))
            write_json_atomic(self.path, data, indent=2)
        return True

    @staticmethod
    def _ttl(ttl_s: int) -> int:
        if not 1 <= ttl_s <= MAX_TTL_S:
            raise TokenError(f"a token lives between 1 and {MAX_TTL_S} seconds")
        return ttl_s

    def verify(self, token: str, *, now: float | None = None) -> Claims:
        """Check signature, expiry and that the run is still active. Raise ``TokenError`` if not."""
        now = time.time() if now is None else now
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            raise TokenError("not a run token")
        try:
            claims = json.loads(_unb64(parts[1]))
            sig = _unb64(parts[2])
            kid = str(claims["kid"])
        except (ValueError, KeyError, TypeError, RecursionError) as exc:
            raise TokenError("unreadable token") from exc
        key = self.keys.key(kid)
        if key is None:
            raise TokenError("signed with a key this gate does not know")
        want = hmac.new(key, f"{PREFIX}.{parts[1]}".encode(), sha256).digest()
        if not hmac.compare_digest(sig, want):
            raise TokenError("bad signature")
        try:
            out = Claims(claims["run"], claims["agent"], tuple(claims["scopes"]),
                         int(claims["iat"]), int(claims["exp"]), kid)  # fmt: skip
        except (KeyError, TypeError, ValueError) as exc:
            raise TokenError("incomplete claims") from exc
        if out.expires <= now:
            raise TokenError("expired")
        if out.issued > now + 30:
            raise TokenError("issued in the future")
        entry = self.get(out.run_id)
        if entry is None or entry["agent"] != out.agent_id:
            raise TokenError("no such identity")
        if entry["status"] != "active":
            raise TokenError("revoked")
        return out


class Inventory:
    """Every agent id the gate has seen, with first and last sighting and how many runs."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = FileLock(path.with_name(path.name + ".lock"))

    def all(self) -> dict[str, dict[str, Any]]:
        return read_json(self.path, {})

    def note_run(self, agent_id: str) -> bool:
        """Record a new run for this agent. Returns True the first time we ever see the agent."""
        now = int(time.time())
        with self._lock:
            data = self.all()
            first = agent_id not in data
            entry = data.get(agent_id, {"first_seen": now, "runs": 0})
            data[agent_id] = {**entry, "last_seen": now, "runs": entry["runs"] + 1}
            write_json_atomic(self.path, data, indent=2)
        return first
