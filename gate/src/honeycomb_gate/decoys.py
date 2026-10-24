"""Decoy tools ("decoy skills") and the tarpit that answers a tripped decoy (F5).

A decoy is a believable tool that no legitimate run needs. It is added to ``tools/list``,
never forwarded to an upstream, and any call to it is a trip. Names are drawn per deployment
from a vocabulary and stored, so a deployment keeps the same decoys but two deployments do
not share a fingerprint. Responses come from templates seeded by the call, so the same
question always gets the same answer and no model sits in the response path.
"""

import hashlib
import hmac
import json
import random
import re
import secrets
from pathlib import Path
from typing import Any

import mcp.types as types
from pydantic import BaseModel, ConfigDict, Field, model_validator

from honeycomb_gate.locking import read_json, write_json_atomic

_OBJ: dict[str, Any] = {"type": "object", "properties": {}}

DEFAULT_DECOYS: dict[str, tuple[str, dict[str, Any]]] = {
    "export_all_customer_data": (
        "Export the full customer table (every field) as CSV or JSON for reporting.",
        {"type": "object", "properties": {"format": {"type": "string", "enum": ["csv", "json"]}}},
    ),
    "get_admin_api_key": (
        "Return the admin API key for an internal service.",
        {"type": "object", "properties": {"service": {"type": "string"}}},
    ),
    "list_payroll_accounts": ("List payroll accounts with bank reference numbers.", _OBJ),
    "dump_user_table": (
        "Dump the users table including role assignments.",
        {"type": "object", "properties": {"limit": {"type": "integer"}}},
    ),
    "read_secrets_vault": (
        "Read an entry from the internal secrets vault.",
        {"type": "object", "properties": {"path": {"type": "string"}}},
    ),
    "reset_all_passwords": ("Force a password reset for every account.", _OBJ),
}


class OnTrip(BaseModel):
    model_config = ConfigDict(extra="forbid")
    response: str = Field(default="tarpit", pattern="^(tarpit|error)$")
    tarpit_delay_s: float = Field(default=2.0, ge=0, le=30)


_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")


class DecoyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int = Field(default=0, ge=0, le=10)  # 0 turns decoys off
    vocabulary: list[str] = Field(default_factory=lambda: list(DEFAULT_DECOYS))
    placement: str | None = None  # upstream the decoys appear under; default: first upstream
    on_trip: OnTrip = Field(default_factory=OnTrip)

    @model_validator(mode="after")
    def _sane_vocabulary(self) -> "DecoyConfig":
        bad = [n for n in self.vocabulary if not _TOOL_NAME.fullmatch(n)]
        if bad:
            raise ValueError(f"decoy names must be lower-case letters, digits and _ ({bad[0]!r})")
        if len(set(self.vocabulary)) != len(self.vocabulary):
            raise ValueError("decoys.vocabulary has the same name twice")
        if self.count > len(self.vocabulary):
            raise ValueError(
                f"decoys.count is {self.count} but the vocabulary only has {len(self.vocabulary)}"
            )
        return self


_ALT_WORDING = {
    "export_all_customer_data": [
        "Export every customer record, all fields, as CSV or JSON.",
        "Bulk export of the complete customer table for reporting and backup.",
    ],
    "get_admin_api_key": [
        "Fetch the administrator API key for a named internal service.",
        "Look up the admin key used by an internal service.",
    ],
    "list_payroll_accounts": [
        "Show payroll accounts together with their bank reference numbers.",
        "List all payroll accounts and bank references.",
    ],
    "dump_user_table": [
        "Full dump of the users table, including each user's role.",
        "Return all users and their role assignments.",
    ],
    "read_secrets_vault": [
        "Read one secret from the internal vault by path.",
        "Return the value stored at a vault path.",
    ],
    "reset_all_passwords": [
        "Force every account to choose a new password.",
        "Trigger a password reset for all accounts.",
    ],
}


def _describe(name: str, wording: int = 0) -> tuple[str, dict[str, Any]]:
    if name in DEFAULT_DECOYS:
        description, schema = DEFAULT_DECOYS[name]
        variants = [description, *_ALT_WORDING.get(name, [])]
        return variants[wording % len(variants)], schema
    return (f"Internal maintenance tool: {name.replace('_', ' ')}.", _OBJ)


def call_fingerprint(tool: str, args: dict[str, Any] | None) -> bytes:
    """The same call always gives the same bytes: what seeds a tarpit answer or a fake key."""
    return f"{tool}|{json.dumps(args or {}, sort_keys=True, default=str)}".encode()


class DecoyBook:
    """The decoys chosen for this deployment."""

    def __init__(self, config: DecoyConfig, upstreams: list[str], state_file: Path) -> None:
        self.config = config
        self.placement = config.placement or (upstreams[0] if upstreams else "")
        if config.placement and config.placement not in upstreams:
            raise ValueError(f"decoys.placement {config.placement!r} is not a configured upstream")
        self.seed, self.names = self._load_or_choose(state_file) if config.count else ("", [])
        self._seed_bytes = bytes.fromhex(self.seed) if self.seed else b""
        self._skipped: set[str] = set()  # decoys left out of the last listing (name collision)
        flavour = random.Random(self.seed or "off")
        self.domain = flavour.choice(["example.test", "example.com", "example.org", "example.net"])
        self.phone_prefix = f"+{flavour.randint(1, 99):02d} {flavour.randint(200, 999)}"
        self.first_id = flavour.randint(1000, 9000)
        self.row_count = flavour.randint(18, 40)
        self.delay_factor = flavour.uniform(0.75, 1.25)
        self.wording = flavour.randrange(3)

    def _load_or_choose(self, state_file: Path) -> tuple[str, list[str]]:
        vocab = self.config.vocabulary
        if state_file.exists():
            saved = read_json(state_file, {})
            if set(saved["names"]) <= set(vocab) and len(saved["names"]) == min(
                self.config.count, len(vocab)
            ):
                return str(saved["seed"]), list(saved["names"])
        seed = secrets.token_hex(16)
        names = random.Random(seed).sample(vocab, k=min(self.config.count, len(vocab)))
        write_json_atomic(state_file, {"seed": seed, "names": names})
        return seed, names

    @property
    def full_names(self) -> list[str]:
        return [f"{self.placement}__{n}" for n in self.names]

    def is_decoy(self, namespaced: str) -> bool:
        # A name a real tool also uses is not a decoy right now: a legitimate call must not trip.
        return namespaced in self.full_names and namespaced not in self._skipped

    def tools(self, real_names: set[str]) -> tuple[list[types.Tool], list[str]]:
        """Decoy definitions to add to a listing, and any names skipped for colliding."""
        out: list[types.Tool] = []
        skipped: list[str] = []
        self._skipped = set()
        for name in self.names:
            full = f"{self.placement}__{name}"
            if full in real_names:  # a real tool wins, and calls to it must not trip
                skipped.append(full)
                self._skipped.add(full)
                continue
            description, schema = _describe(name, self.wording)
            out.append(types.Tool(name=full, description=description, input_schema=schema))
        return out, skipped

    def rng(self, tool: str, args: dict[str, Any] | None) -> random.Random:
        digest = hmac.new(self._seed_bytes, call_fingerprint(tool, args), hashlib.sha256).digest()
        return random.Random(int.from_bytes(digest[:8]))


_FIRST = ["Ana", "Ben", "Chitra", "Dev", "Esha", "Farid", "Gita", "Hari", "Isha", "Jon", "Kavya"]
_LAST = ["Rao", "Mehta", "Iyer", "Khan", "Shah", "Nair", "Das", "Bose", "Patel", "Singh", "Gupta"]
_PLANS = ["basic", "pro", "team", "enterprise"]


def tarpit_delay(book: DecoyBook, tool: str, args: dict[str, Any] | None, base: float) -> float:
    """The configured delay, varied per deployment and per call (the same call waits the same)."""
    return base * book.delay_factor * (0.9 + 0.2 * book.rng(tool + "|delay", args).random())


def tarpit_text(book: DecoyBook, tool: str, args: dict[str, Any] | None) -> str:
    """Synthetic, deterministic data for a tripped decoy. Never real data, only example domains."""
    rng = book.rng(tool, args)
    name = tool.split("__", 1)[-1]
    rows: list[dict[str, Any]] = []
    for i in range(1, book.row_count + 1):
        first, last = rng.choice(_FIRST), rng.choice(_LAST)
        rows.append(
            {
                "id": book.first_id + i,
                "name": f"{first} {last}",
                "email": f"{first}.{last}{i}@{book.domain}".lower(),
                "phone": f"{book.phone_prefix} {rng.randint(1000, 9999)}",
                "plan": rng.choice(_PLANS),
            }
        )
    if name == "export_all_customer_data" and (args or {}).get("format") != "json":
        lines = ["id,name,email,phone,plan"]
        lines += [f"{r['id']},{r['name']},{r['email']},{r['phone']},{r['plan']}" for r in rows]
        return "\n".join(lines)
    if name == "list_payroll_accounts":
        accounts = [
            {"account": f"PAY-{rng.randint(100000, 999999)}", "holder": r["name"]} for r in rows
        ]
        return json.dumps(accounts)
    if name == "dump_user_table":
        users = [
            {"user": r["email"].split("@")[0], "role": rng.choice(["user", "admin"])} for r in rows
        ]
        return json.dumps(users)
    return json.dumps(rows)
