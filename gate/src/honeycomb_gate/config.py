"""Gate configuration (M0 subset of the policy file in docs/PHASE0-SPEC.md section 6)."""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Upstream(BaseModel):
    transport: str = "stdio"
    command: list[str] = Field(min_length=1)


class GateConfig(BaseModel):
    schema_version: int = 1
    event_log: Path = Path(".honeycomb/events.jsonl")
    upstreams: dict[str, Upstream]


def load_config(path: Path) -> GateConfig:
    cfg = GateConfig.model_validate(yaml.safe_load(path.read_text()))
    if cfg.schema_version != 1:
        raise ValueError(f"unsupported schema_version {cfg.schema_version}")
    for name, up in cfg.upstreams.items():
        if "__" in name:
            raise ValueError(f"upstream name {name!r} must not contain '__'")
        if up.transport != "stdio":
            raise ValueError(f"upstream {name!r}: only stdio is supported in M0")
    return cfg
