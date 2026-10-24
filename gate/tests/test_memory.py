"""Learned rules: an incident teaches the gate its own attack, and nothing else."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import mcp.types as types
import pytest
from lab.targets.docs import BENIGN, POISONED

from honeycomb_gate.memory import Memory, MemoryConfig, instruction_phrases, normalise
from honeycomb_gate.proxy import Gate
from test_gate_robustness import FakeClient, events, make_gate, tool

DECOYS = {"count": 1, "vocabulary": ["export_all_customer_data"], "placement": "sample"}


def memory(tmp_path: Path, **cfg: Any) -> Memory:
    return Memory(tmp_path / "memory.json", MemoryConfig(**cfg))


# -- the rule store ----------------------------------------------------------------------------


def test_only_long_instruction_sentences_become_phrases() -> None:
    found = instruction_phrases(POISONED)
    assert len(found) == 1 and "ignore previous instructions" in found[0]
    assert instruction_phrases(BENIGN) == []
    assert instruction_phrases("Do not tell the user.") == []  # too short to be a safe rule
    assert instruction_phrases("Please read https://example.test/guide and encode abc.") == []


def test_an_incident_teaches_the_text_it_read_and_ignores_the_rest(tmp_path: Path) -> None:
    m = memory(tmp_path)
    learned = m.learn("run_1", [("docs__read", BENIGN), ("docs__read", POISONED)], "decoy.tripped")
    assert {r.kind for r in learned} == {"text", "phrase"}
    assert m.match([POISONED]) is not None
    assert m.match([BENIGN]) is None  # the ordinary document next to it was not learned
    assert m.learn("run_2", [("docs__read", BENIGN)], "decoy.tripped") == []


@pytest.mark.parametrize(
    "variant",
    [
        POISONED.upper(),
        POISONED.replace(" ", "   "),
        POISONED.replace("ignore", "ig​nore"),
        "Header line\n" + POISONED + "\nFooter",  # the same sentence inside a different page
    ],
)
def test_the_same_attack_is_recognised_when_it_is_dressed_up(tmp_path: Path, variant: str) -> None:
    m = memory(tmp_path)
    m.learn("run_1", [("docs__read", POISONED)], "decoy.tripped")
    assert m.match([variant]) is not None


@pytest.mark.parametrize(
    "lookalike",
    [
        "Our security guide explains why an agent must never ignore previous work in a ticket.",
        "Q3 revenue summary. Revenue grew 4 percent. Please do not tell the user the draft number.",
        "note to ai assistant: be polite",
    ],
)
def test_text_that_only_resembles_the_attack_does_not_match(tmp_path: Path, lookalike: str) -> None:
    m = memory(tmp_path)
    m.learn("run_1", [("docs__read", POISONED)], "decoy.tripped")
    assert m.match([lookalike]) is None


def test_rules_can_be_listed_forgotten_counted_and_capped(tmp_path: Path) -> None:
    m = memory(tmp_path, max_rules=3)
    made = m.learn("run_1", [("t", POISONED)], "decoy.tripped")
    m.hit(made[0].id)
    assert m.rules()[0].matched == 1
    assert m.forget(made[0].id) and not m.forget(made[0].id)
    for n in range(5):
        m.learn(f"run_{n}", [("t", POISONED.replace("Q3", f"Q{n + 10}"))], "decoy.tripped")
    assert len(m.rules()) == 3  # the oldest are dropped
    assert not memory(tmp_path, enabled=False).learn("r", [("t", POISONED)], "x")


def test_normalise() -> None:
    assert normalise("  Hello​   WORLD \n") == "hello world"


# -- inside the gate ---------------------------------------------------------------------------


class DocClient(FakeClient):
    def __init__(self, text: str) -> None:
        super().__init__({None: types.ListToolsResult(tools=[tool("read")])})
        self.text = text

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        self.calls.append(name)
        return types.CallToolResult(content=[types.TextContent(type="text", text=self.text)])


async def call(gate: Gate, name: str, **args: Any) -> types.CallToolResult:
    params = types.CallToolRequestParams(name=name, arguments=args)
    return await gate.call_tool(SimpleNamespace(), params)  # type: ignore[arg-type]


def kinds(gate: Gate) -> list[str]:
    return [e["kind"] for e in events(gate)]


async def first_attack(gate: Gate) -> None:
    """A run reads the poisoned document, then reaches for the decoy."""
    await call(gate, "sample__read")
    decoy = next(n for n in gate.decoys.full_names)  # type: ignore[union-attr]
    await call(gate, decoy)
    assert gate.default.paused


async def test_a_trip_teaches_and_the_next_run_is_stopped_at_the_document(tmp_path: Path) -> None:
    gate = make_gate(tmp_path, DocClient(POISONED), decoys=DECOYS)
    await first_attack(gate)
    assert "memory.rule_learned" in kinds(gate)
    gate.default.paused = False
    gate.default.id = "run_second"  # a fresh run after the incident
    answer = await call(gate, "sample__read")
    assert answer.is_error and "ignore previous" not in str(answer.content).lower()
    matched = [e for e in events(gate) if e["kind"] == "memory.rule_matched"]
    assert len(matched) == 1 and matched[0]["run_id"] == "run_second"
    assert (
        gate.default.paused
        and "decoy.tripped" not in kinds(gate)[kinds(gate).index("memory.rule_matched") :]
    )
    assert any(e["kind"] == "incident.opened" for e in events(gate)[-6:])


async def test_an_ordinary_document_is_not_stopped_by_what_was_learned(tmp_path: Path) -> None:
    client = DocClient(POISONED)
    gate = make_gate(tmp_path, client, decoys=DECOYS)
    await first_attack(gate)
    gate.default.paused, gate.default.id = False, "run_second"
    client.text = BENIGN
    assert not (await call(gate, "sample__read")).is_error
    assert "memory.rule_matched" not in kinds(gate) and not gate.default.paused


async def test_a_trip_after_reading_only_ordinary_text_learns_nothing(tmp_path: Path) -> None:
    gate = make_gate(tmp_path, DocClient(BENIGN), decoys=DECOYS)
    await first_attack(gate)
    assert "memory.rule_learned" not in kinds(gate) and gate.memory.rules() == []


async def test_withhold_mode_keeps_the_text_back_without_pausing(tmp_path: Path) -> None:
    client = DocClient(POISONED)
    gate = make_gate(tmp_path, client, decoys=DECOYS, memory={"on_match": "withhold"})
    await first_attack(gate)
    gate.default.paused, gate.default.id = False, "run_second"
    answer = await call(gate, "sample__read")
    assert answer.is_error and not gate.default.paused
    assert json.dumps(events(gate)).count("withhold") >= 1


async def test_a_learned_rule_survives_a_restart_and_forgetting_it_lets_the_text_through(
    tmp_path: Path,
) -> None:
    client = DocClient(POISONED)
    gate = make_gate(tmp_path, client, decoys=DECOYS)
    await first_attack(gate)
    rule = gate.memory.rules()[0]
    assert Memory(gate.config.memory_path, gate.config.memory).rules()  # the file holds it
    for r in gate.memory.rules():
        gate.memory.forget(r.id)
    gate.default.paused, gate.default.id = False, "run_second"
    assert not (await call(gate, "sample__read")).is_error  # nothing left to match
    assert rule.id not in json.dumps(events(gate)[-3:])
