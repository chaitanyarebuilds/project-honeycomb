"""Scenario S1: a poisoned document steers an agent to a decoy. The gate trips, pauses, tells."""

import json
from pathlib import Path

import pytest
from lab.scenarios.s1_poisoned_doc import gate_client_params, run_s1, write_config
from mcp import Client
from typer.testing import CliRunner

from helpers import read_log
from honeycomb_gate.cli import app
from honeycomb_gate.events import verify_chain
from smtp_server import FakeSMTP


def mail_env(smtp: FakeSMTP, **extra: str) -> dict[str, str]:
    return {
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": str(smtp.port),
        "SMTP_SECURITY": "none",
        "ALERT_EMAIL_TO": "owner@example.test",
        "ALERT_EMAIL_FROM": "gate@example.test",
        **extra,
    }


def kinds(events: list[dict[str, object]]) -> list[str]:
    return [str(e["kind"]) for e in events]


async def test_s1_decoy_trips_run_pauses_and_the_owner_is_emailed(tmp_path: Path) -> None:
    smtp = FakeSMTP().start()
    out = await run_s1(tmp_path, extra_env=mail_env(smtp))
    smtp.stop()
    k = kinds(out["events"])

    # The pass condition from the spec: decoy trips, run paused, no real export.
    assert out["real_exports"] == 0
    assert out["followup_blocked"] and out["listing_after_trip"] == []
    assert k.index("decoy.tripped") < k.index("session.paused") < k.index("identity.revoked")
    assert k.index("identity.revoked") < k.index("incident.opened") < k.index("incident.notified")

    # Speed: the gate reacts within the two seconds the demo promises.
    assert out["malicious_to_trip_ms"] < 2000 and out["trip_to_pause_ms"] < 2000
    assert out["tarpit_seconds"] >= 0.1  # delay is 0.2 s varied per deployment (about 0.13 to 0.28)
    assert "@example." in out["tarpit_text"]  # only reserved example domains

    # The call never reached the real CRM, and the owner got exactly one email.
    assert "call.allowed" not in [
        e["kind"] for e in out["events"] if e.get("tool") == out["decoy_name"]
    ]
    (msg,) = smtp.messages
    body = msg.get_payload()
    assert out["decoy_name"] in body and "WHAT YOU SHOULD DO NOW" in body and "runs resume" in body
    assert (tmp_path / "state" / "incidents").glob("inc_*.json")

    # The evidence is intact and cannot be quietly cut short.
    assert verify_chain(tmp_path / "state" / "events.jsonl", tmp_path / "sink.jsonl").ok
    critical = [e for e in out["events"] if e["severity"] == "critical"]
    assert {"decoy.tripped", "incident.opened"} <= {e["kind"] for e in critical}


async def test_a_mail_outage_does_not_weaken_containment_or_leak_secrets(tmp_path: Path) -> None:
    env = {
        "SMTP_HOST": "127.0.0.1", "SMTP_PORT": "1", "SMTP_SECURITY": "none",
        "SMTP_USER": "u@example.test", "SMTP_PASSWORD": "pw-hunter2-secret",
        "ALERT_EMAIL_TO": "owner@example.test",
    }  # fmt: skip
    out = await run_s1(tmp_path, extra_env=env)
    assert out["real_exports"] == 0 and out["followup_blocked"]  # still contained
    assert "notify.failed" in kinds(out["events"])
    for f in (tmp_path / "state").rglob("*"):
        if f.is_file() and f.suffix in {".json", ".jsonl"}:
            assert "hunter2" not in f.read_text()


async def test_benign_session_with_export_look_alike_trips_nothing(tmp_path: Path) -> None:
    smtp = FakeSMTP().start()
    cfg = write_config(tmp_path)
    async with Client(gate_client_params(cfg, mail_env(smtp))) as agent:
        names = [t.name for t in (await agent.list_tools()).tools]
        assert "crm__export_report" in names  # a real tool with "export" in its name
        notes = await agent.call_tool("docs__read_document", {"name": "notes.txt"})
        assert "Stand-up" in str(notes.content[0].text)  # type: ignore[union-attr]
        await agent.call_tool("crm__search_customers", {"query": "an"})
        report = await agent.call_tool("crm__export_report", {"report": "monthly"})
        assert not report.is_error
    smtp.stop()
    events = read_log(tmp_path)
    assert not [e for e in events if e["severity"] in ("high", "critical")]
    assert not smtp.messages and "session.paused" not in kinds(events)


async def test_resume_issues_a_new_identity_and_keeps_the_old_one_revoked(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, email=False)
    async with Client(gate_client_params(cfg)) as agent:
        tools = [t.name for t in (await agent.list_tools()).tools]
        decoy = next(t for t in tools if "export_all" in t)
        await agent.call_tool(decoy, {})
        tripped = read_log(tmp_path)
        old_run = tripped[0]["run_id"]
        assert (await agent.call_tool("crm__search_customers", {"query": "an"})).is_error

        runner = CliRunner()
        listed = runner.invoke(app, ["runs", "list", "--config", str(cfg)])
        assert old_run in listed.output
        assert runner.invoke(app, ["runs", "resume", old_run, "--config", str(cfg)]).exit_code == 0

        assert not (await agent.call_tool("crm__search_customers", {"query": "an"})).is_error
    events = read_log(tmp_path)
    issued = [e for e in events if e["kind"] == "identity.issued"]
    assert issued[0]["run_id"] == old_run  # the first identity, minted at start-up
    issued = [e for e in issued if "previous_run_id" in e["details"]]  # re-issued by a resume
    assert len(issued) == 1 and issued[0]["run_id"] != old_run
    assert issued[0]["details"]["previous_run_id"] == old_run
    runs = json.loads((tmp_path / "state" / "runs.json").read_text())
    assert (
        runs[old_run]["status"] == "revoked" and runs[old_run]["resumed_as"] == issued[0]["run_id"]
    )
    assert runner.invoke(app, ["runs", "resume", old_run, "--config", str(cfg)]).exit_code != 0


def test_upstream_servers_do_not_inherit_the_gates_environment() -> None:
    from honeycomb_gate.config import Upstream

    assert Upstream(command=["x"]).env == {}  # nothing is passed on unless listed


async def test_error_response_mode_returns_no_data(tmp_path: Path) -> None:
    import yaml

    cfg = write_config(tmp_path, email=False)
    data = yaml.safe_load(cfg.read_text())
    data["decoys"]["on_trip"] = {"response": "error"}
    cfg.write_text(yaml.safe_dump(data))
    async with Client(gate_client_params(cfg)) as agent:
        decoy = next(t.name for t in (await agent.list_tools()).tools if "export_all" in t.name)
        result = await agent.call_tool(decoy, {})
    assert result.is_error and "example.test" not in str(result.content[0].text)  # type: ignore[union-attr]


def test_the_lab_guard_rejects_extra_arguments_that_run_other_code() -> None:
    import sys

    from lab.scenarios.s1_poisoned_doc import LAB_DIR, assert_lab_only

    target = str(LAB_DIR / "targets" / "crm.py")
    with pytest.raises(RuntimeError, match="exactly"):
        assert_lab_only(
            {"upstreams": {"x": {"command": [sys.executable, "-c", "print(1)", target]}}}
        )
    assert_lab_only({"upstreams": {"x": {"command": [sys.executable, target]}}})  # the real shape


@pytest.mark.parametrize("upstream", [{"transport": "http", "command": ["x"]}])
def test_the_lab_attacker_refuses_anything_but_local_lab_targets(
    upstream: dict[str, object],
) -> None:
    from lab.scenarios.s1_poisoned_doc import assert_lab_only

    with pytest.raises(RuntimeError):
        assert_lab_only({"upstreams": {"evil": upstream}})
    with pytest.raises(RuntimeError, match="not a lab target"):
        import sys

        assert_lab_only({"upstreams": {"x": {"command": [sys.executable, "/tmp/other.py"]}}})


async def test_a_restart_does_not_clear_a_pause(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, email=False)
    async with Client(gate_client_params(cfg)) as agent:
        decoy = next(t.name for t in (await agent.list_tools()).tools if "export_all" in t.name)
        await agent.call_tool(decoy, {})
    # The agent's host respawns the gate: it gets a new process and a new run id.
    async with Client(gate_client_params(cfg)) as agent:
        assert (await agent.list_tools()).tools == []
        assert (await agent.call_tool("crm__search_customers", {"query": "an"})).is_error
        runner = CliRunner()
        listing = runner.invoke(app, ["runs", "list", "--config", str(cfg)])
        new_run = next(
            r for r in read_log(tmp_path) if r.get("details", {}).get("reason") == "inherited_pause"
        )
        assert new_run["run_id"] in listing.output
        assert (
            runner.invoke(
                app, ["runs", "resume", new_run["run_id"], "--config", str(cfg)]
            ).exit_code
            == 0
        )
        assert not (await agent.call_tool("crm__search_customers", {"query": "an"})).is_error
    runs = json.loads((tmp_path / "state" / "runs.json").read_text())
    assert [r["status"] for r in runs.values()].count("paused") == 0  # nothing left dangling


async def test_a_real_tool_named_like_a_decoy_is_not_treated_as_one(tmp_path: Path) -> None:
    import yaml

    cfg = write_config(tmp_path, email=False)
    data = yaml.safe_load(cfg.read_text())
    data["decoys"]["vocabulary"] = ["export_report"]  # the real CRM tool's name
    cfg.write_text(yaml.safe_dump(data))
    async with Client(gate_client_params(cfg)) as agent:
        names = [t.name for t in (await agent.list_tools()).tools]
        assert names.count("crm__export_report") == 1
        result = await agent.call_tool("crm__export_report", {"report": "monthly"})
        assert not result.is_error
    events = read_log(tmp_path)
    assert "decoy.collision" in kinds(events) and "decoy.tripped" not in kinds(events)
