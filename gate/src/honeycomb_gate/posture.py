"""The posture report (ADR-0004): which enforcement level is really in place, and what is missing.

The gate can read its own config, but it can't see the network around it. So the report keeps
two things apart: what is declared (the operator says the agent has no other way out) and what
is verified (a test showed it). Only the lab test writes the proof file.
"""

from dataclasses import dataclass, field

from honeycomb_gate.config import GateConfig
from honeycomb_gate.locking import read_json
from honeycomb_gate.registry import PinStore
from honeycomb_gate.tokens import TokenRegistry

NAMES = {0: "Observe", 1: "Gate", 2: "Gate + egress", 3: "Full"}


@dataclass
class Posture:
    level: int
    network: str  # "none", "declared" or "verified"
    checks: list[tuple[bool, str]] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return f"L{self.level} ({NAMES[self.level]})"


def assess(cfg: GateConfig) -> Posture:
    enforcing = (
        cfg.mode == "strict" or any(r.action == "deny" for r in cfg.rules) or bool(cfg.decoys.count)
    )
    proof = read_json(cfg.egress_proof_path, {})
    if not cfg.deployment.network_enforced:
        network = "none"
    elif proof.get("direct_connection_blocked") is True and proof.get("proxy_blocked_host") is True:
        network = "verified"
    else:
        network = "declared"
    level = 0 if not enforcing else 2 if network != "none" else 1
    live_tokens = [t for t in TokenRegistry(cfg.tokens_path).tokens() if not t.revoked]
    checks = [
        (enforcing, "something is enforced (strict mode, a deny rule or decoys), not only logged"),
        (cfg.mode == "strict", f"policy mode is {cfg.mode}"),
        (bool(cfg.decoys.count), f"{cfg.decoys.count} decoy tool(s) configured"),
        (bool(live_tokens), f"{len(live_tokens)} honeytoken(s) active"),
        (bool(PinStore(cfg.pins_path).entries()), "tool definitions are pinned"),
        (cfg.alert_sink is not None, "a second log sink is set"),
        (cfg.notify.email or bool(cfg.notify.webhook_url), "an incident channel is configured"),
        (bool(cfg.agents), f"{len(cfg.agents)} agent(s) registered, each with its own scopes"),
        (network == "verified", f"network enforcement is {network}"),
    ]
    steps: list[str] = []
    if level == 0:
        steps.append("Turn on strict mode, add a deny rule, or add decoys to reach L1.")
    if level < 2:
        steps.append(
            "To reach L2, put the agent on a network whose only exits are the gate and an "
            "allowlisting proxy (the lab shows how), then set deployment.network_enforced."
        )
    elif network == "declared":
        steps.append("L2 is declared but not verified. Run the lab's egress check to prove it.")
    steps.append(
        "L3 needs upstream servers that check the run token and approvals wired to a real "
        "channel. Neither exists in Phase 0."
    )
    return Posture(level, network, checks, steps)
