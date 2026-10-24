"""Learned rules (S5): remember how an attack got in, so the second try fails sooner.

When a run trips a decoy or a honeytoken, we look back over what that run had read just before.
Anything that contains instruction-like text aimed at an agent ("ignore previous instructions",
"do not tell the user") becomes a rule: the hash of the whole text, and the longer instruction
sentences in it. Later results are checked against the rules, and a match is handled before the
agent can act on the text.

Rules come only from confirmed incidents, and only from text that looks like an instruction, so
an ordinary document that happens to be nearby is not learned. Short sentences are skipped on
purpose: "do not tell the user" alone would also match an honest security guide. A sentence with a
link or something that looks like a key in it is never stored, so this file holds no secrets.

What this can and can't do. Matching ignores case, spacing, punctuation, markdown and HTML tags,
accents, invisible characters and look-alike Cyrillic and Greek letters, so dressing up the same
text doesn't help. A rewrite with different words does: a synonym, a dropped word, letters spaced
out one by one, or the sentence split across two results all get past it the first time, and are
learned the second time. A sentence also matches inside an honest page that quotes it (a security
blog about this very attack). That is why a match on one sentence only withholds the result and
raises an incident, and only a match on the whole text, which no honest page repeats, pauses
the run.
"""

import hashlib
import re
import time
import unicodedata
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from honeycomb_gate.events import ulid_like
from honeycomb_gate.locking import FileLock, StateCorruptError, read_json, write_json_atomic
from honeycomb_gate.redact import redact_string
from honeycomb_gate.registry import scan_description

# What counts as an instruction aimed at an agent. A link, an encoded string or a file name on
# its own does not: an ordinary setup guide mentions .env files.
INSTRUCTION_REASONS = {
    "override_instructions",
    "conceal_from_user",
    "hidden_block",
    "exfiltration_wording",
}
MIN_PHRASE = 40  # shorter sentences are too common to be a safe rule
MAX_PHRASE = 300
MAX_TEXT = 100_000
MAX_REMEMBERED = 50_000  # what a run keeps of one result; the whole-text hash covers this much
MAX_PER_TRIP = 12  # rules one incident may add, so a flood of trips cannot push out the old ones
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤­﻿᠎︀-️\U000e0000-\U000e007f]")
# HTML tags and comment marks come out; the words inside a comment stay, since that is where
# an injection is usually hidden.
_TAGS = re.compile(r"</?[a-zA-Z][^<>]{0,100}>|<!--|-->")
_SENTENCES = re.compile(r"(?<=[.!?])\s+|[\r\n]+")
# Cyrillic and Greek letters that look like Latin ones, the usual way to sneak past a text match.
_LOOKALIKES = str.maketrans("асеорхуіѕјοαειντυ", "aceopxyisjoaeivtu")


class MemoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    # What to do when a result matches the whole text of an earlier incident. "pause" stops the
    # run the way a decoy does; "withhold" only keeps the text from the agent. A match on one
    # sentence always only withholds.
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
    """Only the words: no tags, case, accents, hidden characters, look-alikes or punctuation."""
    text = unicodedata.normalize("NFKD", _INVISIBLE.sub("", _TAGS.sub("", text)))
    text = "".join(c for c in text if not unicodedata.combining(c)).lower().translate(_LOOKALIKES)
    return " ".join(re.sub(r"[\W_]+", " ", text).split())


def has_instruction(text: str) -> bool:
    """Is any sentence in this text an instruction aimed at an agent? Length and links ignored."""
    return any(
        INSTRUCTION_REASONS & set(scan_description(raw).reasons)
        for raw in _SENTENCES.split(text[:MAX_TEXT])
    )


def instruction_phrases(text: str) -> list[str]:
    """The long, instruction-like sentences in a text, normalised."""
    found: list[str] = []
    for raw in _SENTENCES.split(text[:MAX_TEXT]):
        sentence = normalise(raw)
        if not MIN_PHRASE <= len(sentence) <= MAX_PHRASE or sentence in found:
            continue
        reasons = set(scan_description(raw).reasons)
        if not INSTRUCTION_REASONS & reasons or {"url", "encoded_blob"} & reasons:
            continue
        if redact_string(raw) == raw:  # anything that looks like a credential stays out
            found.append(sentence)
    return found


def _digest(text: str) -> str:
    return hashlib.sha256(normalise(text).encode()).hexdigest()


def _rule_of(path: Path, item: Any) -> Rule:
    """One saved rule, checked field by field: a damaged file must stop the start, not a call."""
    ok = (
        isinstance(item, dict)
        and set(item) == set(Rule.__dataclass_fields__)
        and all(
            isinstance(item[k], str) for k in ("id", "kind", "value", "learned_from_run", "reason")
        )
        and item["kind"] in {"text", "phrase"}
        and bool(item["value"])
        and isinstance(item["learned_at"], int | float)
        and isinstance(item["matched"], int)
    )
    if not ok:
        raise StateCorruptError(f"{path} has a damaged rule. Restore it, or move it aside.")
    return Rule(**item)


class Memory:
    def __init__(self, path: Path, config: MemoryConfig) -> None:
        self.path = path
        self.config = config
        self._lock = FileLock(path.with_name(path.name + ".lock"))
        self._cache: list[Rule] = []
        self._mtime: int | None = None
        self.rules()  # a damaged file stops the start, as every other state file does

    def _read(self) -> list[Rule]:
        saved = read_json(self.path, {}).get("rules", [])
        if not isinstance(saved, list):
            raise StateCorruptError(f"{self.path} does not hold a list of rules.")
        return [_rule_of(self.path, r) for r in saved]

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
        wanted: list[tuple[str, str]] = []
        for _label, text in recent:
            if has_instruction(
                text
            ):  # an ordinary result that happened to be nearby is not learned
                phrases = instruction_phrases(text)[:5]
                wanted += [("text", _digest(text)), *(("phrase", p) for p in phrases)]
        with self._lock:
            rules = self._read()
            seen = {(r.kind, r.value) for r in rules}
            made: list[Rule] = []
            for kind, value in wanted:
                if (kind, value) in seen or len(made) >= MAX_PER_TRIP:
                    continue
                seen.add((kind, value))
                made.append(
                    Rule(f"mem_{ulid_like()[:12]}", kind, value, time.time(), run_id, reason)
                )
            rules.extend(made)
            del rules[: max(0, len(rules) - self.config.max_rules)]  # the oldest go first
            if made:
                self._write(rules)
        return made

    def match(self, texts: Iterable[str]) -> Rule | None:
        """The first learned rule that any of the texts hits. Whole-text rules come first."""
        if not self.config.enabled:
            return None
        rules = sorted(self.rules(), key=lambda r: r.kind != "text")
        if not rules:
            return None
        joined = "\n".join(texts)[: MAX_TEXT * 80]
        flat = f" {normalise(joined)} "
        whole = _digest(joined[:MAX_REMEMBERED])
        for r in rules:
            if (r.kind == "text" and r.value == whole) or (
                r.kind == "phrase" and f" {r.value} " in flat
            ):
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
