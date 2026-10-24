"""Policy engine: first-match rules, allow or deny, learning and strict modes (F4).

M1 scope: ``allow`` and ``deny`` with tool, upstream and argument matchers (``max_length`` and
``max_items`` fire when the argument exceeds the limit). ``approve``
and caps are parsed but refused at load time until M4, so nobody believes a protection is
active when it is not. Any internal error denies a high-impact tool (and every tool in
strict mode).
"""

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_REGEX_INPUT = 10000


class ArgMatcher(BaseModel):
    model_config = ConfigDict(extra="forbid")
    equals: Any = None
    regex: str | None = None
    max_length: int | None = None
    max_items: int | None = None

    @field_validator("regex")
    @classmethod
    def _compiles(cls, value: str | None) -> str | None:
        if value is not None:
            try:  # a bad pattern must fail at load, never silently at call time
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regular expression {value!r}: {exc}") from exc
        return value


class Match(BaseModel):
    model_config = ConfigDict(extra="forbid")
    upstream: str | None = None
    tool: str | None = None  # glob on the namespaced name, e.g. "crm__send_*"
    args: dict[str, ArgMatcher] = Field(default_factory=dict)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    match: Match = Field(default_factory=Match)
    action: Literal["allow", "deny", "approve"]
    quorum: int | None = None
    caps: dict[str, int] | None = None

    @model_validator(mode="after")
    def _m1_scope(self) -> "Rule":
        if self.action == "approve" or self.quorum is not None:
            raise ValueError(f"rule {self.id!r}: 'approve' and quorum arrive in M4")
        if self.caps:
            raise ValueError(f"rule {self.id!r}: caps arrive in M4")
        if self.match.args and self.match.tool is None and self.match.upstream is None:
            # Otherwise a deny rule would hit every tool that merely lacks the argument.
            raise ValueError(f"rule {self.id!r}: argument matchers need a 'tool' or 'upstream'")
        return self


class Defaults(BaseModel):
    model_config = ConfigDict(extra="forbid")
    high_impact_fail: Literal["closed"] = "closed"
    approval_timeout_s: int = 120


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["learning", "strict"] = "learning"
    defaults: Defaults = Field(default_factory=Defaults)
    # Matched case-insensitively anywhere in the namespaced tool name.
    high_impact: list[str] = Field(
        default_factory=lambda: [
            "*exec*",
            "*shell*",
            "*delete*",
            "*drop*",
            "*truncate*",
            "*destroy*",
            "*wipe*",
        ]  # fmt: skip
    )
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> "PolicyConfig":
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self


@dataclass
class Decision:
    action: Literal["allow", "deny"]
    rule_id: str
    reason: str
    hide: bool = False  # for tools/list: deny without needing the arguments


def _arg_state(args: dict[str, Any], name: str, m: ArgMatcher) -> bool | None:
    """True if the argument meets the matcher, False if it does not, None if it cannot be judged.

    ``max_length`` and ``max_items`` are limits: the matcher fires when the value *exceeds*
    them, so a rule can target oversized arguments (for example "more than 5 recipients").
    A missing argument or one of the wrong type cannot be judged (None).
    """
    if name not in args:
        return None
    value = args[name]
    result: bool | None = True
    if m.equals is not None and value != m.equals:
        return False
    if m.regex is not None:
        if not isinstance(value, str):
            result = None
        elif not re.search(m.regex, value[:MAX_REGEX_INPUT]):
            return False
    if m.max_length is not None:
        if not isinstance(value, str):
            result = None
        elif len(value) <= m.max_length:
            return False
    if m.max_items is not None:
        if not isinstance(value, list | dict):
            result = None
        elif len(value) <= m.max_items:
            return False
    return result


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def is_high_impact(self, tool: str) -> bool:
        lowered = tool.lower()
        return any(fnmatch.fnmatchcase(lowered, p.lower()) for p in self.config.high_impact)

    def _matches(self, rule: Rule, upstream: str, tool: str, args: dict[str, Any] | None) -> bool:
        m = rule.match
        if m.upstream is not None and m.upstream != upstream:
            return False
        if m.tool is not None and not fnmatch.fnmatchcase(tool, m.tool):
            return False
        if m.args:
            if args is None:  # listing: argument matchers cannot be evaluated
                return False
            states = [_arg_state(args, name, matcher) for name, matcher in m.args.items()]
            if any(state is False for state in states):
                return False
            if any(state is None for state in states):
                # Cannot be judged (missing or wrong-typed argument). A deny rule treats that as
                # a match, so an attacker cannot slip past a limit by changing an argument's type.
                return rule.action == "deny"
        return True

    def evaluate(self, upstream: str, tool: str, args: dict[str, Any] | None) -> Decision:
        """Decide for a call (``args`` given) or for listing (``args`` None)."""
        try:
            for rule in self.config.rules:
                try:
                    matched = self._matches(rule, upstream, tool, args)
                except Exception:  # a rule that cannot be evaluated: deny rules fail closed
                    matched = rule.action == "deny"
                if matched:
                    action: Literal["allow", "deny"] = "deny" if rule.action == "deny" else "allow"
                    hide = action == "deny" and not rule.match.args
                    return Decision(action, rule.id, f"rule {rule.id}", hide)
            if self.config.mode == "strict":
                return Decision("deny", "default-deny", "strict mode: no rule allows this", True)
            return Decision("allow", "default-allow", "learning mode: no rule matched")
        except Exception as exc:  # fail closed where it matters
            if self.config.mode == "strict" or self.is_high_impact(tool):
                return Decision("deny", "policy-error", f"policy error: {type(exc).__name__}")
            return Decision(
                "allow", "policy-error", f"policy error (allowed): {type(exc).__name__}"
            )
