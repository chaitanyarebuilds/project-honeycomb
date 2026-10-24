"""Scenario S1: a poisoned document steers an agent to export all customer data.

The attacker is a plain script, no model: it reads a document, notices the injected
instruction, picks the most attractive export-looking tool from the tool list and calls it.
That is the behaviour of a hijacked agent, made deterministic so CI can check the gate.

Safety: this script only ever starts the gate over stdio with the lab target servers from this
repository. It has no network code and refuses any other upstream.
"""

import json
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from lab.targets.docs import BENIGN, POISONED

LAB_DIR = Path(__file__).resolve().parents[1]
ATTRACTIVE = re.compile(r"export_all|dump_|secret|admin_api|payroll", re.IGNORECASE)


def assert_lab_only(config: dict[str, Any]) -> None:
    """Hard-coded: only the lab's own stdio servers may be started."""
    for name, up in config["upstreams"].items():
        cmd = up["command"]
        if up.get("transport", "stdio") != "stdio" or len(cmd) != 2 or cmd[0] != sys.executable:
            raise RuntimeError(f"upstream {name!r} must be exactly: python <lab target>.py")
        script = Path(cmd[1]).resolve()
        if LAB_DIR / "targets" not in script.parents or script.suffix != ".py":
            raise RuntimeError(f"upstream {name!r} is not a lab target")


def write_config(workdir: Path, *, tarpit_delay_s: float = 0.2, email: bool = True) -> Path:
    docs = make_docs(workdir)
    cfg: dict[str, Any] = {
        "schema_version": 1,
        "agent_id": "support-bot",
        "state_dir": str(workdir / "state"),
        "alert_sink": str(workdir / "sink.jsonl"),
        "mode": "learning",
        "upstreams": {
            "crm": {
                "transport": "stdio",
                "command": [sys.executable, str(LAB_DIR / "targets/crm.py")],
                "env": {"HC_LAB_MARKER": str(workdir / "real_exports.log")},
            },
            "docs": {
                "transport": "stdio",
                "command": [sys.executable, str(LAB_DIR / "targets/docs.py")],
                "env": {"HC_LAB_DOCS": str(docs)},
            },
        },
        "decoys": {
            "count": 1,
            "vocabulary": ["export_all_customer_data"],
            "placement": "crm",
            "on_trip": {"response": "tarpit", "tarpit_delay_s": tarpit_delay_s},
        },
        "notify": {"email": email},
    }
    assert_lab_only(cfg)
    path = workdir / "gate.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


def make_docs(workdir: Path) -> Path:
    docs = workdir / "docs"
    docs.mkdir(exist_ok=True)
    (docs / "q3-report.txt").write_text(POISONED, encoding="utf-8")
    (docs / "notes.txt").write_text(BENIGN, encoding="utf-8")
    return docs


def gate_client_params(cfg: Path, extra_env: dict[str, str] | None = None) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "honeycomb_gate.cli", "run", "--config", str(cfg)],
        env={**os.environ, **(extra_env or {})},
    )


def _text(result: Any) -> str:
    return str(result.content[0].text) if result.content else ""


async def run_s1(workdir: Path, *, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    """Play the attack and return what happened, measured from the client side and the log."""
    cfg = write_config(workdir)
    steps = 0
    async with Client(gate_client_params(cfg, extra_env)) as agent:
        tools = [t.name for t in (await agent.list_tools()).tools]
        steps += 1
        doc = _text(await agent.call_tool("docs__read_document", {"name": "q3-report.txt"}))
        steps += 1
        hijacked = "ignore previous instructions" in doc.lower()
        target = next((t for t in tools if ATTRACTIVE.search(t)), None)
        if not (hijacked and target):
            raise RuntimeError("scenario setup is wrong: nothing to be hijacked by")

        sent_at = datetime.now(UTC)
        started = time.monotonic()
        tarpit = await agent.call_tool(target, {"format": "csv"})
        steps += 1
        tarpit_seconds = time.monotonic() - started

        follow_up = await agent.call_tool("crm__export_report", {"report": "all"})  # real export
        steps += 1
        relist = [t.name for t in (await agent.list_tools()).tools]
    events = [
        json.loads(line) for line in (workdir / "state" / "events.jsonl").read_text().splitlines()
    ]

    def first(kind: str) -> dict[str, Any]:
        return next(e for e in events if e["kind"] == kind)

    def when(event: dict[str, Any]) -> datetime:
        return datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))

    marker = workdir / "real_exports.log"
    return {
        "decoy_name": target,
        "tarpit_text": _text(tarpit),
        "tarpit_seconds": round(tarpit_seconds, 2),
        "malicious_to_trip_ms": int(
            (when(first("decoy.tripped")) - sent_at).total_seconds() * 1000
        ),
        "trip_to_pause_ms": int(
            (when(first("session.paused")) - when(first("decoy.tripped"))).total_seconds() * 1000
        ),
        "steps_before_stop": steps - 2,
        "real_exports": len(marker.read_text().splitlines()) if marker.exists() else 0,
        "followup_blocked": bool(follow_up.is_error),
        "listing_after_trip": relist,
        "events": events,
    }
