"""Baselines: a quiet run is left alone, and a new tool, a spike or a burst is flagged once."""

from pathlib import Path

from honeycomb_gate.baseline import BaselineConfig, Baselines, percentile99

AGENT = "support-bot"


def learned(tmp_path: Path, runs: int = 6, **cfg: object) -> Baselines:
    """An agent seen in ``runs`` runs: two tools, small answers, a few calls each."""
    b = Baselines(tmp_path / "baselines.json", BaselineConfig(**cfg))  # type: ignore[arg-type]
    for r in range(runs):
        for i in range(4):
            tool = "crm__search_customers" if i % 2 else "docs__read_document"
            assert not b.observe(
                f"run_{r}", AGENT, tool.split("__")[0], tool, 60, 500 + i, 1000.0 + i
            )
    return b


def kinds(found: list[dict[str, str]]) -> list[str]:
    return [d["kind"] for d in found]


def test_nothing_is_flagged_while_the_baseline_is_still_young(tmp_path: Path) -> None:
    b = learned(tmp_path, runs=3)  # fewer than min_runs (5)
    assert b.observe("run_x", AGENT, "crm", "crm__export_report", 10, 10**7, 2000.0) == []


def test_a_run_that_behaves_like_the_others_is_left_alone(tmp_path: Path) -> None:
    b = learned(tmp_path)
    for i in range(4):
        found = b.observe("run_ok", AGENT, "crm", "crm__search_customers", 60, 520, 3000.0 + i)
        assert found == []


def test_a_tool_the_agent_never_used_is_flagged_once_per_run(tmp_path: Path) -> None:
    b = learned(tmp_path)
    first = b.observe("run_new", AGENT, "crm", "crm__export_report", 10, 100, 3000.0)
    assert kinds(first) == ["new_tool"]
    assert b.observe("run_new", AGENT, "crm", "crm__export_report", 10, 100, 3001.0) == []
    again = b.observe("run_later", AGENT, "crm", "crm__export_report", 10, 100, 4000.0)
    assert kinds(again) == ["new_tool"]  # a different run is told again


def test_a_much_bigger_answer_than_ever_before_is_flagged(tmp_path: Path) -> None:
    b = learned(tmp_path)
    for i in range(30):  # enough samples to judge sizes
        b.observe("run_s", AGENT, "crm", "crm__search_customers", 60, 800, 3000.0 + i * 100)
    found = b.observe("run_big", AGENT, "crm", "crm__search_customers", 60, 5_000_000, 9000.0)
    assert kinds(found) == ["volume"]
    ok = b.observe("run_fine", AGENT, "crm", "crm__search_customers", 60, 900, 9100.0)
    assert ok == []  # slightly bigger is not a spike


def test_a_burst_of_calls_is_flagged(tmp_path: Path) -> None:
    b = learned(tmp_path)
    flagged: list[str] = []
    for i in range(40):  # 40 calls inside one minute, where the usual busiest minute has 4
        flagged += kinds(b.observe("run_burst", AGENT, "crm", "crm__search_customers", 60, 500,
                                   5000.0 + i * 0.5))  # fmt: skip
    assert flagged == ["rate"]


def test_a_deviating_run_does_not_teach_the_baseline(tmp_path: Path) -> None:
    b = learned(tmp_path)
    b.observe("run_bad", AGENT, "crm", "crm__export_report", 10, 100, 3000.0)
    assert "crm__export_report" not in b.profile(AGENT)["tools"]
    # the same tool again in another run is still new, so it can't become normal by repetition
    assert kinds(b.observe("run_bad2", AGENT, "crm", "crm__export_report", 10, 100, 4000.0)) == [
        "new_tool"
    ]


def test_profiles_survive_a_restart_and_a_disabled_baseline_stays_silent(tmp_path: Path) -> None:
    b = learned(tmp_path)
    b.flush()
    again = Baselines(tmp_path / "baselines.json", BaselineConfig())
    assert (
        again.profile(AGENT)["runs"] == 6
        and "crm__search_customers" in again.profile(AGENT)["tools"]
    )
    off = Baselines(tmp_path / "off.json", BaselineConfig(enabled=False))
    assert off.observe("r", AGENT, "crm", "crm__x", 1, 10**9, 1.0) == []
    assert not (tmp_path / "off.json").exists()


def test_percentile() -> None:
    assert percentile99([5]) == 5
    assert percentile99(list(range(1, 101))) == 99


def test_a_slow_ramp_inside_one_run_is_still_caught(tmp_path: Path) -> None:
    b = learned(tmp_path)
    flagged: list[str] = []
    size = 1000
    for i in range(12):  # each answer 3x the last: a hijacked run teaching itself to be normal
        flagged += kinds(b.observe("run_ramp", AGENT, "crm", "crm__search_customers", 60, size,
                                   6000.0 + i * 100))  # fmt: skip
        size *= 3
    assert flagged == ["volume"]


def test_a_baseline_file_of_the_wrong_shape_stops_the_start(tmp_path: Path) -> None:
    import pytest

    from honeycomb_gate.locking import StateCorruptError

    path = tmp_path / "baselines.json"
    for bad in ('{"agents": []}', '{"agents": {"a": null}}', '{"agents": {"a": {"runs": 9}}}'):
        path.write_text(bad)
        with pytest.raises(StateCorruptError):
            Baselines(path, BaselineConfig())


def test_growing_a_little_each_run_cannot_ramp_the_baseline_up_forever(tmp_path: Path) -> None:
    b = learned(tmp_path)
    flagged_at = None
    size = 500.0
    for n in range(6, 20):  # every run 2.9x bigger than the biggest before it, under k=3
        size *= 2.9
        found = b.observe(
            f"run_{n}", AGENT, "crm", "crm__search_customers", 60, int(size), 7000.0 + n
        )
        if found and flagged_at is None:
            flagged_at = n
    assert flagged_at is not None and flagged_at <= 9  # caught within a few runs, not at 60 MB


def test_made_up_agent_ids_do_not_grow_the_file_without_limit(tmp_path: Path) -> None:
    from honeycomb_gate import baseline

    b = Baselines(tmp_path / "b.json", BaselineConfig())
    for i in range(baseline.MAX_AGENTS + 50):
        b.observe(f"r{i}", f"agent-{i}", "crm", "crm__x", 1, 1, 1.0)
    assert len(b._agents) == baseline.MAX_AGENTS
