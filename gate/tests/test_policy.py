from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from honeycomb_gate.config import load_config
from honeycomb_gate.policy import PolicyConfig, PolicyEngine


def engine(**kw: Any) -> PolicyEngine:
    return PolicyEngine(PolicyConfig.model_validate(kw))


RULES = [
    {"id": "deny-shell", "match": {"tool": "*__exec*"}, "action": "deny"},
    {
        "id": "deny-bulk-email",
        "match": {"tool": "crm__send_email", "args": {"recipients": {"max_items": 5}}},
        "action": "deny",
    },
    {"id": "allow-crm", "match": {"upstream": "crm"}, "action": "allow"},
]


def test_first_match_wins() -> None:
    e = engine(mode="strict", rules=RULES)
    assert e.evaluate("crm", "crm__exec_sql", {}).rule_id == "deny-shell"
    assert e.evaluate("crm", "crm__get_customer", {"id": 1}).action == "allow"


def test_argument_limit_fires_only_when_exceeded() -> None:
    e = engine(mode="strict", rules=RULES)
    small = e.evaluate("crm", "crm__send_email", {"recipients": ["a@x.test"] * 5})
    big = e.evaluate("crm", "crm__send_email", {"recipients": ["a@x.test"] * 6})
    assert (small.action, small.rule_id) == ("allow", "allow-crm")  # benign look-alike
    assert (big.action, big.rule_id) == ("deny", "deny-bulk-email")


def test_regex_and_equals_matchers() -> None:
    e = engine(
        rules=[
            {
                "id": "no-prod",
                "match": {
                    "tool": "a__q",
                    "args": {"db": {"regex": "^prod"}, "mode": {"equals": "write"}},
                },
                "action": "deny",
            }
        ]
    )
    assert e.evaluate("a", "a__q", {"db": "prod-1", "mode": "write"}).action == "deny"
    assert e.evaluate("a", "a__q", {"db": "prod-1", "mode": "read"}).action == "allow"
    assert e.evaluate("a", "a__q", {"db": "test", "mode": "write"}).action == "allow"
    assert e.evaluate("a", "a__q", {}).action == "deny"  # cannot be judged: deny rules fail closed
    assert e.evaluate("a", "a__other", {}).action == "allow"  # a different tool is untouched


def test_learning_allows_unknown_and_strict_denies_unknown() -> None:
    assert engine(mode="learning").evaluate("x", "x__t", {}).action == "allow"
    strict = engine(mode="strict").evaluate("x", "x__t", {})
    assert strict.action == "deny" and strict.hide


def test_listing_hides_unconditional_denies_but_not_argument_conditioned_ones() -> None:
    e = engine(rules=RULES)
    assert e.evaluate("crm", "crm__exec_sql", None).hide
    assert not e.evaluate("crm", "crm__send_email", None).hide


def test_a_rule_that_errors_at_runtime_fails_closed_if_it_is_a_deny_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import honeycomb_gate.policy as policy

    def boom(*_: object) -> None:
        raise RuntimeError("simulated")

    monkeypatch.setattr(policy, "_arg_state", boom)
    args = {"x": {"equals": 1}}
    deny = {"id": "d", "match": {"tool": "a__t", "args": args}, "action": "deny"}
    allow = {"id": "a", "match": {"tool": "a__t", "args": args}, "action": "allow"}
    assert engine(rules=[deny]).evaluate("a", "a__t", {"x": 1}).action == "deny"
    # An allow rule that errors is skipped; strict mode then denies by default.
    assert engine(mode="strict", rules=[allow]).evaluate("a", "a__t", {"x": 1}).action == "deny"


@pytest.mark.parametrize(
    "rule",
    [
        {"id": "r", "action": "approve"},
        {"id": "r", "action": "allow", "quorum": 2},
        {"id": "r", "action": "allow", "caps": {"per_minute": 3}},
        {"id": "r", "action": "allow", "unknown_field": 1},
    ],
)
def test_unsupported_features_are_refused_loudly(rule: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"rules": [rule]})


def test_duplicate_rule_ids_and_bad_config_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"rules": [RULES[0], RULES[0]]})
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"upstreams": {"a": {"command": ["x"]}}, "mod": "strict"}))
    with pytest.raises(ValidationError):  # a typo must not silently fall back to defaults
        load_config(cfg)


def test_argument_matchers_need_a_tool_or_upstream() -> None:
    with pytest.raises(ValidationError, match="need a 'tool' or 'upstream'"):
        PolicyConfig.model_validate(
            {"rules": [{"id": "r", "match": {"args": {"x": {"equals": 1}}}, "action": "deny"}]}
        )


@pytest.mark.parametrize("name", ["a__b", "x__y"])
def test_upstream_names_cannot_contain_separator(name: str, tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"upstreams": {name: {"command": ["x"]}}}))
    with pytest.raises(ValueError):
        load_config(cfg)


def test_deny_limits_cannot_be_bypassed_by_changing_an_argument_type_or_omitting_it() -> None:
    e = engine(
        rules=[
            {
                "id": "no-bulk",
                "match": {"tool": "crm__send", "args": {"to": {"max_items": 5}}},
                "action": "deny",
            }
        ]
    )
    for evasive in ({"to": "a,b,c,d,e,f,g"}, {}, {"to": 7}, {"to": None}):
        assert e.evaluate("crm", "crm__send", evasive).action == "deny", evasive
    assert e.evaluate("crm", "crm__send", {"to": ["a"] * 5}).action == "allow"  # at the limit
    assert e.evaluate("crm", "crm__send", {"to": {str(i): i for i in range(6)}}).action == "deny"


def test_allow_rules_stay_strict_about_argument_types() -> None:
    e = engine(
        mode="strict",
        rules=[
            {
                "id": "ok",
                "match": {"tool": "a__t", "args": {"to": {"equals": "ops"}}},
                "action": "allow",
            }
        ],
    )
    assert e.evaluate("a", "a__t", {"to": "ops"}).action == "allow"
    assert e.evaluate("a", "a__t", {}).action == "deny"


def test_a_bad_regex_is_rejected_when_the_policy_loads() -> None:
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate(
            {"rules": [{"id": "r", "match": {"args": {"x": {"regex": "("}}}, "action": "deny"}]}
        )


def test_high_impact_patterns_cover_common_dangerous_names_in_any_case() -> None:
    e = engine()
    for name in ("crm__bulk_delete", "sh__Exec", "db__DropTable", "ops__run_shell", "x__wipe_all"):
        assert e.is_high_impact(name), name
    for name in ("crm__get_customer", "docs__read_file", "crm__search"):
        assert not e.is_high_impact(name), name


@pytest.mark.parametrize("name", ["a_", "A", "a b", "a.b", "1a", "", "a" * 40, "é"])
def test_ambiguous_upstream_names_are_rejected(name: str, tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"upstreams": {name: {"command": ["x"]}}}))
    with pytest.raises(ValueError):
        load_config(cfg)
