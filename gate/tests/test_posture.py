"""The posture report claims no more than is enforced, and keeps declared apart from proven."""

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from helpers import write_config
from honeycomb_gate.cli import app
from honeycomb_gate.config import load_config
from honeycomb_gate.posture import assess


def level(tmp_path: Path, **extra: Any) -> tuple[int, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    report = assess(load_config(write_config(tmp_path, **extra)))
    return report.level, report.network


def proof(tmp_path: Path, **flags: bool) -> None:
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state" / "egress-proof.json").write_text(json.dumps(flags))


def test_a_gate_that_only_watches_is_l0(tmp_path: Path) -> None:
    assert level(tmp_path) == (0, "none")


def test_enforcing_something_is_l1(tmp_path: Path) -> None:
    assert level(tmp_path / "a", mode="strict") == (1, "none")
    deny = {"rules": [{"id": "d", "match": {"tool": "*__exec*"}, "action": "deny"}]}
    assert level(tmp_path / "b", **deny) == (1, "none")
    assert level(
        tmp_path / "c", decoys={"count": 1, "vocabulary": ["export_all_customer_data"]}
    ) == (1, "none")


def test_declared_network_enforcement_is_l2_but_not_verified(tmp_path: Path) -> None:
    assert level(tmp_path, mode="strict", deployment={"network_enforced": True}) == (2, "declared")


def test_a_proof_file_alone_does_not_raise_the_level(tmp_path: Path) -> None:
    proof(tmp_path, direct_connection_blocked=True, proxy_blocked_host=True)
    assert level(tmp_path, mode="strict") == (1, "none")  # nobody declared the network


def test_both_proofs_make_it_verified_and_half_a_proof_does_not(tmp_path: Path) -> None:
    cfg = {"mode": "strict", "deployment": {"network_enforced": True}}
    proof(tmp_path / "a", direct_connection_blocked=True)
    assert level(tmp_path / "a", **cfg) == (2, "declared")
    proof(tmp_path / "b", direct_connection_blocked=True, proxy_blocked_host=True)
    assert level(tmp_path / "b", **cfg) == (2, "verified")


def test_no_setup_reaches_l3_in_phase_zero(tmp_path: Path) -> None:
    proof(tmp_path, direct_connection_blocked=True, proxy_blocked_host=True)
    report = assess(load_config(write_config(tmp_path, mode="strict",
                                             deployment={"network_enforced": True})))  # fmt: skip
    assert report.level == 2 and any("L3" in step for step in report.next_steps)


def test_the_command_prints_the_level_and_what_is_missing(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, mode="strict")
    result = CliRunner().invoke(app, ["posture", "--config", str(cfg)])
    assert result.exit_code == 0
    assert "Enforcement level: L1 (Gate)" in result.stdout
    assert "[x] policy mode is strict" in result.stdout and "[ ] a second log sink" in result.stdout
    assert "To reach L2" in result.stdout
