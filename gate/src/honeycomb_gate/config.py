"""Gate configuration: upstreams, state locations and the policy (see PHASE0-SPEC section 6)."""

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from honeycomb_gate.policy import PolicyConfig


class Upstream(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transport: str = "stdio"
    command: list[str] = Field(min_length=1)


class GateConfig(PolicyConfig):
    schema_version: int = 1
    agent_id: str = "default"
    state_dir: Path = Path(".honeycomb")
    event_log: Path | None = None
    alert_sink: Path | None = None  # second sink for high and critical events and chain checkpoints
    # Seconds a live tool definition may be reused between calls. 0 (the default) re-checks the
    # upstream on every call, so a rug pull is caught on the very next call. A higher value
    # saves a round trip per call but leaves a window in which a changed tool is still trusted.
    recheck_ttl_s: float = 0.0
    upstreams: dict[str, Upstream]

    @property
    def event_log_path(self) -> Path:
        return self.event_log or self.state_dir / "events.jsonl"

    @property
    def pins_path(self) -> Path:
        return self.state_dir / "pins.json"


def load_config(path: Path) -> GateConfig:
    cfg = GateConfig.model_validate(yaml.safe_load(path.read_text()))
    if cfg.schema_version != 1:
        raise ValueError(f"unsupported schema_version {cfg.schema_version}")
    for name, up in cfg.upstreams.items():
        # Tool names are routed as "<upstream>__<tool>", so upstream names must be unambiguous.
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
            raise ValueError(
                f"upstream name {name!r} must be 1 to 32 characters: lower-case letters, "
                "digits and '-', starting with a letter"
            )
        if up.transport != "stdio":
            raise ValueError(f"upstream {name!r}: only stdio is supported until M3")
    return cfg
