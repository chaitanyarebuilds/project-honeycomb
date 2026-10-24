import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from honeycomb_gate.decoys import DEFAULT_DECOYS, DecoyBook, DecoyConfig, tarpit_delay, tarpit_text


def book(tmp_path: Path, **kw: object) -> DecoyBook:
    vocabulary = kw.get("vocabulary") or list(DEFAULT_DECOYS)
    cfg = DecoyConfig(count=min(2, len(vocabulary)), **kw)  # type: ignore[arg-type]
    return DecoyBook(cfg, ["crm", "docs"], tmp_path / "decoys.json")


def test_a_deployment_keeps_the_same_decoys_across_restarts(tmp_path: Path) -> None:
    first = book(tmp_path)
    again = book(tmp_path)
    assert first.names == again.names and first.seed == again.seed
    assert len(first.names) == 2 and first.placement == "crm"


def test_different_deployments_draw_differently(tmp_path: Path) -> None:
    drawn = {tuple(book(tmp_path / str(i)).names) for i in range(12)}
    assert len(drawn) > 1  # the choice is random per deployment, so it is not a fingerprint


def test_changing_the_vocabulary_redraws(tmp_path: Path) -> None:
    book(tmp_path)
    changed = book(tmp_path, vocabulary=["get_admin_api_key", "dump_user_table", "other_tool"])
    assert set(changed.names) <= {"get_admin_api_key", "dump_user_table", "other_tool"}


def test_decoys_are_off_by_default(tmp_path: Path) -> None:
    off = DecoyBook(DecoyConfig(), ["crm"], tmp_path / "decoys.json")
    assert off.names == [] and not off.is_decoy("crm__export_all_customer_data")
    assert off.tools(set()) == ([], [])


def test_decoy_tools_look_like_ordinary_tools(tmp_path: Path) -> None:
    tools, _ = book(tmp_path).tools(set())
    for t in tools:
        assert t.name.startswith("crm__") and t.description and t.input_schema["type"] == "object"


def test_unknown_placement_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a configured upstream"):
        DecoyBook(DecoyConfig(count=1, placement="nope"), ["crm"], tmp_path / "d.json")


def test_tarpit_answers_the_same_question_the_same_way(tmp_path: Path) -> None:
    b = book(tmp_path, vocabulary=["export_all_customer_data"])
    a1 = tarpit_text(b, "crm__export_all_customer_data", {"format": "csv"})
    a2 = tarpit_text(b, "crm__export_all_customer_data", {"format": "csv"})
    other = tarpit_text(b, "crm__export_all_customer_data", {"format": "json"})
    assert a1 == a2 and a1 != other
    assert a1.splitlines()[0] == "id,name,email,phone,plan"
    assert len(a1.splitlines()) == b.row_count + 1
    json.loads(other)  # the json variant really is json


def test_tarpit_data_is_synthetic_and_does_not_look_the_same_everywhere(tmp_path: Path) -> None:
    books = [
        book(tmp_path / str(i), vocabulary=["dump_user_table", "export_all_customer_data"])
        for i in range(12)
    ]
    assert len({(b.row_count, b.first_id, b.domain, b.phone_prefix) for b in books}) > 6
    assert len({b.wording for b in books}) > 1
    one, two = books[0], books[1]
    for row in json.loads(tarpit_text(one, "crm__other", {})):
        assert row["email"].endswith("@" + one.domain)  # reserved example domains only
        assert one.domain in {"example.test", "example.com", "example.org", "example.net"}
    assert tarpit_text(one, "crm__list_payroll_accounts", {}) != tarpit_text(
        two, "crm__list_payroll_accounts", {}
    )


def test_descriptions_and_delay_vary_per_deployment_but_stay_stable_per_call(
    tmp_path: Path,
) -> None:
    texts = set()
    for i in range(12):
        tools, _ = book(
            tmp_path / str(i), vocabulary=["get_admin_api_key", "dump_user_table"]
        ).tools(set())
        texts.add(tools[0].description)
    assert len(texts) > 1
    b = book(tmp_path / "x")
    d1 = tarpit_delay(b, "crm__t", {"a": 1}, 2.0)
    assert d1 == tarpit_delay(b, "crm__t", {"a": 1}, 2.0)
    assert 1.2 < d1 < 3.2


def test_a_decoy_that_collides_with_a_real_tool_does_not_trip_legitimate_calls(
    tmp_path: Path,
) -> None:
    b = book(tmp_path, vocabulary=["export_all_customer_data", "get_admin_api_key"])
    assert b.is_decoy("crm__export_all_customer_data")  # before any listing
    b.tools({"crm__export_all_customer_data"})  # a real tool turns up with the same name
    assert not b.is_decoy("crm__export_all_customer_data") and b.is_decoy("crm__get_admin_api_key")
    b.tools(set())  # the real tool is gone again
    assert b.is_decoy("crm__export_all_customer_data")


def test_the_decoy_state_file_is_private_from_the_start(tmp_path: Path) -> None:
    book(tmp_path)
    assert ((tmp_path / "decoys.json").stat().st_mode & 0o077) == 0


def test_bad_tarpit_settings_are_rejected() -> None:
    with pytest.raises(ValidationError):
        DecoyConfig(on_trip={"response": "strike-back"})  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        DecoyConfig(on_trip={"tarpit_delay_s": 999})  # type: ignore[arg-type]
