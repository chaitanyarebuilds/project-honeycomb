"""Gate configuration: upstreams, state locations and the policy (see PHASE0-SPEC section 6)."""

from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from honeycomb_gate.decoys import DecoyConfig
from honeycomb_gate.notify import NotifyConfig
from honeycomb_gate.policy import PolicyConfig

# Tool names are routed as "<upstream>__<tool>", so upstream names must be unambiguous.
UpstreamName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{0,31}$")]


class Upstream(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transport: Literal["stdio"] = "stdio"  # more transports arrive in M3
    command: list[str] = Field(min_length=1)
    # Extra environment for this upstream only. The gate's own environment (mail credentials,
    # API keys) is deliberately not passed on.
    env: dict[str, str] = Field(default_factory=dict)


class GateConfig(PolicyConfig):
    schema_version: Literal[1] = 1
    agent_id: str = "default"
    state_dir: Path = Path(".honeycomb")
    event_log: Path | None = None
    alert_sink: Path | None = None  # second sink for high and critical events and chain checkpoints
    # Seconds a live tool definition may be reused between calls. 0 (the default) re-checks the
    # upstream on every call, so a rug pull is caught on the very next call. A higher value
    # saves a round trip per call but leaves a window in which a changed tool is still trusted.
    recheck_ttl_s: float = 0.0
    call_timeout_s: float = Field(default=120.0, gt=0)  # a hung upstream can't hold a call forever
    decoys: DecoyConfig = Field(default_factory=DecoyConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    upstreams: dict[UpstreamName, Upstream]

    @model_validator(mode="after")
    def _cross_checks(self) -> "GateConfig":
        place = self.decoys.placement
        if self.decoys.count and place and place not in self.upstreams:
            raise ValueError(f"decoys.placement {place!r} is not one of the upstreams")
        if self.state_dir.is_file():
            raise ValueError(f"state_dir {self.state_dir} is a file, not a folder")
        return self

    @property
    def event_log_path(self) -> Path:
        return self.event_log or self.state_dir / "events.jsonl"

    @property
    def pins_path(self) -> Path:
        return self.state_dir / "pins.json"

    @property
    def tokens_path(self) -> Path:
        return self.state_dir / "tokens.json"

    @property
    def runs_path(self) -> Path:
        return self.state_dir / "runs.json"

    @property
    def decoys_path(self) -> Path:
        return self.state_dir / "decoys.json"

    @property
    def incidents_dir(self) -> Path:
        return self.state_dir / "incidents"


def load_config(path: Path) -> GateConfig:
    return GateConfig.model_validate(yaml.safe_load(path.read_text()))
