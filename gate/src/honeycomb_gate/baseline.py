"""Behaviour baselines (F9): what is normal for an agent, and a flag when a run is not.

For each agent id we keep which tools it uses, how many calls a run makes in its busiest minute,
and how big its requests and answers are. Plain counts and percentiles, no model. Once an agent
has been seen in ``min_runs`` runs, a run that does something new (a tool never used before, a
busy minute well above the usual peak, an answer far bigger than any before) gets a
``baseline.deviation`` event. That is a signal for a person, not a block.

A run that deviates stops teaching the baseline, so a hijacked agent can't slowly make its own
misbehaviour look normal. Time of day is recorded in the profile but not judged yet.
"""

import math
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from honeycomb_gate.locking import FileLock, StateCorruptError, read_json, write_json_atomic

WINDOW_S = 60.0
MAX_RUNS_KEPT = 2000
FLUSH_EVERY = 25
SIZE_FLOOR = 4096  # a tiny answer is never a "spike", whatever the history says


class BaselineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    min_runs: int = Field(default=5, ge=1)  # runs to learn from before anything is flagged
    k: float = Field(default=3.0, gt=1)  # how many times the usual top value counts as a deviation
    rate_floor: int = Field(default=20, ge=1)  # calls in one minute that are never flagged
    samples: int = Field(default=500, ge=20)  # how many sizes and run peaks we remember


def percentile99(values: list[int]) -> int:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(0.99 * len(ordered)) - 1)]


@dataclass
class _Run:
    agent_id: str
    calls: deque[float] = field(default_factory=deque)
    peak: int = 0
    flagged: set[tuple[str, str]] = field(default_factory=set)
    biggest: int = 0
    deviated: bool = False
    counted: bool = False


def _new_profile() -> dict[str, Any]:
    return {"runs": 0, "tools": {}, "upstreams": [], "peaks": {}, "size_peaks": {},
            "arg_sizes": [], "hours": [0] * 24}  # fmt: skip


def _checked(path: Path, agents: Any) -> dict[str, dict[str, Any]]:
    """The saved profiles, if they have the shape we wrote. A damaged file stops the start."""
    shape = {"runs": int, "tools": dict, "upstreams": list, "peaks": dict, "size_peaks": dict,
             "arg_sizes": list, "hours": list}  # fmt: skip
    ok = isinstance(agents, dict) and all(
        isinstance(p, dict) and all(isinstance(p.get(k), t) for k, t in shape.items())
        for p in agents.values()
    )
    if not ok:
        raise StateCorruptError(
            f"{path} does not look like a baseline file. Restore it from a backup, or move it "
            "aside (keep it as evidence) to learn the baselines again."
        )
    return agents  # type: ignore[no-any-return]


class Baselines:
    def __init__(self, path: Path, config: BaselineConfig) -> None:
        self.path = path
        self.config = config
        self._lock = FileLock(path.with_name(path.name + ".lock"))
        self._agents = _checked(path, read_json(path, {}).get("agents", {}))
        self._dirty: set[str] = set()
        self._runs: dict[str, _Run] = {}
        self._since_flush = 0

    def profile(self, agent_id: str) -> dict[str, Any]:
        return self._agents.setdefault(agent_id, _new_profile())

    def observe(
        self, run_id: str, agent_id: str, upstream: str, tool: str, arg_size: int,
        result_size: int, now: float | None = None,
    ) -> list[dict[str, Any]]:  # fmt: skip
        """Judge one finished call against the baseline, then learn from it. Returns deviations."""
        if not self.config.enabled:
            return []
        now = time.time() if now is None else now
        run = self._runs.setdefault(run_id, _Run(agent_id))
        while len(self._runs) > MAX_RUNS_KEPT:  # a long-lived gate must not grow without limit
            del self._runs[next(iter(self._runs))]
        profile = self.profile(agent_id)
        run.calls.append(now)
        while run.calls and now - run.calls[0] > WINDOW_S:
            run.calls.popleft()
        run.peak = max(run.peak, len(run.calls))
        run.biggest = max(run.biggest, result_size)

        found: list[dict[str, Any]] = []
        if profile["runs"] >= self.config.min_runs:
            cfg = self.config
            if tool not in profile["tools"]:
                found.append({"kind": "new_tool", "detail": "this agent has never used this tool"})
            # Each run is judged against the other runs, never against its own history.
            sizes = [v for r, v in profile["size_peaks"].items() if r != run_id]
            if len(sizes) >= cfg.min_runs:
                limit = max(cfg.k * percentile99(sizes), SIZE_FLOOR)
                if result_size > limit:
                    usual = percentile99(sizes)
                    detail = f"answer of {result_size} bytes, earlier runs topped out near {usual}"
                    found.append({"kind": "volume", "detail": detail})
            peaks = [v for r, v in profile["peaks"].items() if r != run_id]
            if len(peaks) >= cfg.min_runs:
                limit = max(cfg.k * percentile99(peaks), cfg.rate_floor)
                if len(run.calls) > limit:
                    found.append({"kind": "rate", "detail": f"{len(run.calls)} calls in a minute, "
                                  f"usual busiest minute is {percentile99(peaks)}"})  # fmt: skip
        fresh = [d for d in found if (d["kind"], tool) not in run.flagged]
        run.flagged.update((d["kind"], tool) for d in fresh)
        if found:
            run.deviated = True
        if not run.deviated:  # a deviating run does not get to move the baseline
            self._learn(run, run_id, profile, upstream, tool, arg_size, now)
            self._dirty.add(agent_id)
        self._since_flush += 1
        if self._since_flush >= FLUSH_EVERY:
            self.flush()
        return fresh

    def _learn(
        self, run: _Run, run_id: str, profile: dict[str, Any], upstream: str, tool: str,
        arg_size: int, now: float,
    ) -> None:  # fmt: skip
        if not run.counted:
            run.counted = True
            profile["runs"] += 1
        profile["tools"][tool] = profile["tools"].get(tool, 0) + 1
        if upstream not in profile["upstreams"]:
            profile["upstreams"].append(upstream)
        cap = self.config.samples
        for name, value in (("peaks", run.peak), ("size_peaks", run.biggest)):
            profile[name][run_id] = value
            while len(profile[name]) > cap:  # oldest first: dicts keep their insertion order
                del profile[name][next(iter(profile[name]))]
        profile["arg_sizes"].append(arg_size)
        del profile["arg_sizes"][:-cap]
        profile["hours"][time.gmtime(now).tm_hour] += 1

    def flush(self) -> None:
        """Save what this process learned, without wiping what another gate saved meanwhile."""
        with self._lock:
            saved = read_json(self.path, {}).get("agents", {})
            saved.update({a: self._agents[a] for a in self._dirty})
            write_json_atomic(self.path, {"agents": saved}, indent=2)
        self._since_flush = 0

    @staticmethod
    def load(path: Path) -> dict[str, dict[str, Any]]:
        """For the CLI: the saved profiles, read without a running gate."""
        return _checked(path, read_json(path, {}).get("agents", {}))
