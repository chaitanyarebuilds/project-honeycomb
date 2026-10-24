"""Policy engine: first-match rules, allow, deny or approve, learning and strict modes (F4).

Rules match on tool, upstream and argument matchers (``max_length`` and ``max_items`` fire when
the argument exceeds the limit). An ``approve`` rule needs a person to say yes, optionally
several (``quorum``). ``caps`` limit how much one rule's tools may do: calls per minute, rows in
a result, bytes in a result. Any internal error denies a high-impact tool (and every tool in
strict mode).
"""

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_REGEX_INPUT = 10000
CAPS = {"per_minute", "max_rows", "max_result_bytes"}


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
    quorum: int | None = Field(default=None, ge=1, le=10)
    caps: dict[str, int] | None = None

    @model_validator(mode="after")
    def _checks(self) -> "Rule":
        if self.quorum is not None and self.action != "approve":
            raise ValueError(f"rule {self.id!r}: quorum only makes sense on an 'approve' rule")
        if self.caps:
            unknown = set(self.caps) - CAPS
            if unknown or any(v < 1 for v in self.caps.values()):
                raise ValueError(f"rule {self.id!r}: caps are {sorted(CAPS)}, each at least 1")
            if self.action == "deny":
                raise ValueError(f"rule {self.id!r}: a deny rule has nothing to cap")
        if self.match.args and self.match.tool is None and self.match.upstream is None:
            # Otherwise a deny rule would hit every tool that merely lacks the argument.
            raise ValueError(f"rule {self.id!r}: argument matchers need a 'tool' or 'upstream'")
        return self


class Defaults(BaseModel):
    model_config = ConfigDict(extra="forbid")
    high_impact_fail: Literal["closed"] = "closed"
    approval_timeout_s: int = Field(default=120, ge=1)  # a request nobody answers by then is denied
    approval_wait_s: float = Field(default=20, ge=0)  # how long one call waits before "pending"
    approval_ttl_s: int = Field(default=600, ge=1)  # how long an approved call may still be used


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
    action: Literal["allow", "deny", "approve"]
    rule_id: str
    reason: str
    hide: bool = False  # for tools/list: deny without needing the arguments
    quorum: int = 1
    caps: dict[str, int] = field(default_factory=dict)


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
        if not isinstance(value, str) or len(value) > MAX_REGEX_INPUT:
            result = None  # can't be judged: a deny rule fails closed, so padding can't dodge it
        elif not re.search(m.regex, value):
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
        if m.tool is not None and not fnmatch.fnmatchcase(tool.lower(), m.tool.lower()):
            return False
        if m.args:
            if args is None:  # listing: argument matchers cannot be evaluated
                return False
            states = [_arg_state(args, name, matcher) for name, matcher in m.args.items()]
            if any(state is False for state in states):
                return False
            if any(state is None for state in states):
                # Cannot be judged (missing or wrong-typed argument). Deny, approve and capped
                # rules treat that as a match, so an attacker cannot slip past a limit (more than
                # five recipients, say) by changing an argument's type.
                return rule.action in {"deny", "approve"} or bool(rule.caps)
        return True

    def evaluate(self, upstream: str, tool: str, args: dict[str, Any] | None) -> Decision:
        """Decide for a call (``args`` given) or for listing (``args`` None)."""
        try:
            for rule in self.config.rules:
                try:
                    matched = self._matches(rule, upstream, tool, args)
                except Exception:  # a rule that cannot be evaluated: restricting rules fail closed
                    matched = rule.action in {"deny", "approve"} or bool(rule.caps)
                if matched:
                    hide = rule.action == "deny" and not rule.match.args
                    return Decision(
                        rule.action, rule.id, f"rule {rule.id}", hide,
                        rule.quorum or 1, dict(rule.caps or {}),
                    )  # fmt: skip
            if self.config.mode == "strict":
                return Decision("deny", "default-deny", "strict mode: no rule allows this", True)
            return Decision("allow", "default-allow", "learning mode: no rule matched")
        except Exception as exc:  # fail closed where it matters
            if self.config.mode == "strict" or self.is_high_impact(tool):
                return Decision("deny", "policy-error", f"policy error: {type(exc).__name__}")
            return Decision(
                "allow", "policy-error", f"policy error (allowed): {type(exc).__name__}"
            )
