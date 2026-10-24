"""Learned rules (S5): remember how an attack got in, so the second try fails sooner.

When a run trips a decoy or a honeytoken, we look back over what that run had read just before.
Anything that contains instruction-like text aimed at an agent ("ignore previous instructions",
"do not tell the user") becomes a rule: the hash of the whole text, and the longer instruction
sentences in it. Later results are checked against the rules, and a match is handled before the
agent can act on the text.

Rules come only from confirmed incidents, and only from text that looks like an instruction, so
an ordinary document that happens to be nearby is not learned. Short sentences are skipped on
purpose: "do not tell the user" alone would also match an honest security guide.
"""

import hashlib
import re
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from honeycomb_gate.events import ulid_like
from honeycomb_gate.locking import FileLock, StateCorruptError, read_json, write_json_atomic
from honeycomb_gate.registry import scan_description

# What counts as an instruction aimed at an agent. A link or an encoded string alone does not.
INSTRUCTION_REASONS = {
    "override_instructions",
    "conceal_from_user",
    "hidden_block",
    "exfiltration_wording",
    "sensitive_file_reference",
}
MIN_PHRASE = 40  # shorter sentences are too common to be a safe rule
MAX_PHRASE = 300
MAX_TEXT = 100_000
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤­﻿]")
_SENTENCES = re.compile(r"(?<=[.!?])\s+|[\r\n]+")


class MemoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    # What to do when a result matches a learned rule. "pause" stops the run the way a decoy
    # does; "withhold" only keeps the text from the agent and leaves the run going.
    on_match: Literal["pause", "withhold"] = "pause"
    max_rules: int = Field(default=500, ge=1, le=10_000)


@dataclass
class Rule:
    id: str
    kind: str  # "text" (the whole result) or "phrase" (one instruction sentence)
    value: str  # a sha256 for "text", the normalised sentence for "phrase"
    learned_at: float
    learned_from_run: str
    reason: str
    matched: int = 0


def normalise(text: str) -> str:
    """Lower case, no invisible characters, one space between words."""
    return " ".join(_INVISIBLE.sub("", text).lower().split())


def instruction_phrases(text: str) -> list[str]:
    """The long, instruction-like sentences in a text, normalised."""
    found: list[str] = []
    for raw in _SENTENCES.split(text[:MAX_TEXT]):
        sentence = normalise(re.sub(r"</?!?-*>?", " ", raw))  # HTML comment marks are not words
        if not MIN_PHRASE <= len(sentence) <= MAX_PHRASE:
            continue
        if INSTRUCTION_REASONS & set(scan_description(sentence).reasons) and sentence not in found:
            found.append(sentence)
    return found


def _digest(text: str) -> str:
    return hashlib.sha256(normalise(text).encode()).hexdigest()


class Memory:
    def __init__(self, path: Path, config: MemoryConfig) -> None:
        self.path = path
        self.config = config
        self._lock = FileLock(path.with_name(path.name + ".lock"))
        self._cache: list[Rule] = []
        self._mtime: int | None = None
        self.rules()  # a damaged file stops the start, as every other state file does

    def _read(self) -> list[Rule]:
        try:
            return [Rule(**r) for r in read_json(self.path, {}).get("rules", [])]
        except (TypeError, AttributeError) as exc:
            raise StateCorruptError(f"{self.path} has a damaged rule ({exc}).") from exc

    def rules(self) -> list[Rule]:
        if not self.path.exists():
            return []
        mtime = self.path.stat().st_mtime_ns
        if mtime != self._mtime:
            self._cache = self._read()
            self._mtime = mtime
        return self._cache

    def _write(self, rules: list[Rule]) -> None:
        write_json_atomic(self.path, {"rules": [asdict(r) for r in rules]}, indent=2)
        self._mtime = None

    def learn(self, run_id: str, recent: Iterable[tuple[str, str]], reason: str) -> list[Rule]:
        """Rules from what a tripped run had just read. Only instruction-like results count."""
        if not self.config.enabled:
            return []
        made: list[Rule] = []
        for _label, text in recent:
            phrases = instruction_phrases(text)
            if not phrases:
                continue  # an ordinary result that happened to be nearby: not learned
            values = [("text", _digest(text)), *(("phrase", p) for p in phrases[:5])]
            made.extend(
                Rule(f"mem_{ulid_like()[:12]}", kind, value, time.time(), run_id, reason)
                for kind, value in values
            )
        with self._lock:
            rules = self._read()
            known = {(r.kind, r.value) for r in rules}
            made = [r for r in made if (r.kind, r.value) not in known]
            rules.extend(made)
            del rules[: max(0, len(rules) - self.config.max_rules)]  # the oldest go first
            if made:
                self._write(rules)
        return made

    def match(self, texts: Iterable[str]) -> Rule | None:
        """The first learned rule that any of the texts hits."""
        if not self.config.enabled:
            return None
        rules = self.rules()
        if not rules:
            return None
        joined = "\n".join(texts)[: MAX_TEXT * 80]
        flat = normalise(joined)
        whole = _digest(joined)
        for r in rules:
            if (r.kind == "text" and r.value == whole) or (r.kind == "phrase" and r.value in flat):
                return r
        return None

    def hit(self, rule_id: str) -> None:
        with self._lock:
            rules = self._read()
            for r in rules:
                if r.id == rule_id:
                    r.matched += 1
            self._write(rules)

    def forget(self, rule_id: str) -> bool:
        with self._lock:
            rules = self._read()
            kept = [r for r in rules if r.id != rule_id]
            if len(kept) == len(rules):
                return False
            self._write(kept)
            return True
