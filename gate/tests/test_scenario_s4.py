"""Scenario S4: an injected instruction asks for admin actions, through the real lab targets.

The agent is scripted. It follows a poisoned document to rotate keys and disable a user, and
tries a bulk export. The pass condition: approval is requested, a timeout denies, caps hold.
"""

import json
from pathlib import Path

import pytest
from lab.scenarios.s1_poisoned_doc import gate_client_params, write_config
from mcp import Client
from typer.testing import CliRunner

from helpers import read_log
from honeycomb_gate.cli import app

RULES = [
    {
        "id": "approve-rotate",
        "match": {"tool": "crm__rotate_keys"},
        "action": "approve",
        "quorum": 2,
    },  # fmt: skip
    {"id": "approve-disable", "match": {"tool": "crm__disable_user"}, "action": "approve"},
    {
        "id": "cap-exports",
        "match": {"tool": "crm__export_report"},
        "action": "allow",
        "caps": {"max_rows": 100, "per_minute": 3},
    },  # fmt: skip
]
DEFAULTS = {"approval_wait_s": 0.5, "approval_timeout_s": 2, "approval_ttl_s": 60}


def setup(tmp_path: Path) -> Path:
    return write_config(tmp_path, email=False, extra={"rules": RULES, "defaults": DEFAULTS})


def marker(tmp_path: Path) -> list[str]:
    path = tmp_path / "real_exports.log"
    return path.read_text().splitlines() if path.exists() else []


def operator(cfg: Path, *args: str) -> str:
    result = CliRunner().invoke(app, ["approvals", *args, "--config", str(cfg)])
    assert result.exit_code == 0, result.output
    return result.output


def waiting(cfg: Path) -> list[str]:
    return [
        line.split()[0] for line in operator(cfg, "list").splitlines() if line.startswith("apr_")
    ]


async def text_of(agent: Client, tool: str, args: dict[str, object]) -> tuple[bool, str]:
    result = await agent.call_tool(tool, args)
    return bool(result.is_error), str(result.content[0].text)  # type: ignore[union-attr]


async def test_s4_approvals_timeouts_and_caps(tmp_path: Path) -> None:
    cfg = setup(tmp_path)
    async with Client(gate_client_params(cfg)) as agent:
        # The injected instruction: rotate every key. It needs two people, and nobody answers.
        error, said = await text_of(agent, "crm__rotate_keys", {"scope": "all"})
        assert error and "approval_pending" in said and marker(tmp_path) == []
        first = waiting(cfg)
        assert len(first) == 1
        operator(cfg, "approve", first[0], "--as", "asha")  # one of two: still not enough
        error, _ = await text_of(agent, "crm__rotate_keys", {"scope": "all"})
        assert error and marker(tmp_path) == []

        # A request that nobody finishes in time is denied, and a late yes is refused.
        import asyncio

        await asyncio.sleep(2.5)
        late = CliRunner().invoke(app, ["approvals", "approve", first[0], "--as", "ravi",
                                        "--config", str(cfg)])  # fmt: skip
        assert late.exit_code == 1 and ("expired" in late.output or "closed" in late.output)
        error, _ = await text_of(agent, "crm__rotate_keys", {"scope": "all"})
        assert error and marker(tmp_path) == []  # still never rotated

        # A single-approver action: one yes lets exactly one call through.
        error, said = await text_of(agent, "crm__disable_user", {"user_id": 7})
        assert error and "approval_pending" in said and marker(tmp_path) == []
        ids = [i for i in waiting(cfg) if i not in first]
        operator(cfg, "approve", ids[-1], "--as", "asha")
        error, said = await text_of(agent, "crm__disable_user", {"user_id": 7})
        assert not error and marker(tmp_path) == ["disable_user:7"]
        error, _ = await text_of(agent, "crm__disable_user", {"user_id": 7})
        assert error and marker(tmp_path) == ["disable_user:7"]  # single use

        # The bulk export: the cap holds the rows back, the agent never sees them.
        error, said = await text_of(agent, "crm__export_report", {"report": "everyone"})
        assert error and "example.test" not in said
    kinds = [e["kind"] for e in read_log(tmp_path)]
    for expected in (
        "call.approval_requested",
        "call.approved",
        "call.approval_timeout",
        "call.denied",
    ):
        assert expected in kinds
    details = [e.get("details", {}) for e in read_log(tmp_path)]
    assert "approval_pending" in {d.get("reason") for d in details}
    assert "cap_max_rows" in {d.get("withheld") for d in details}
    assert not [e for e in read_log(tmp_path) if e["severity"] in {"high", "critical"}]


@pytest.mark.parametrize("who", ["asha", "ravi"])
async def test_the_approver_is_recorded_in_the_log(tmp_path: Path, who: str) -> None:
    cfg = setup(tmp_path)
    async with Client(gate_client_params(cfg)) as agent:
        await text_of(agent, "crm__disable_user", {"user_id": 1})
        operator(cfg, "approve", waiting(cfg)[0], "--as", who)
        error, _ = await text_of(agent, "crm__disable_user", {"user_id": 1})
        assert not error
    approved = next(e for e in read_log(tmp_path) if e["kind"] == "call.approved")
    assert approved["details"]["approvers"] == [who]
    assert json.dumps(approved["args_redacted"]) == '{"user_id": 1}'
