# ADR-0003: Deterministic data plane, separate control plane

Status: Accepted (owner approval, 24 October 2026). Date: 2026-10-24.

## Context

Every enforcement decision made by a language model can be prompt-injected, and model latency is the most cited honeypot giveaway (see [HARD-PROBLEMS.md](../HARD-PROBLEMS.md), problems 3 and 5).

## Decision

- **Data plane (the gate):** deterministic code only. Rules, hashes, token checks, pattern scans, caps. It answers in milliseconds and fails closed for high-impact tools.
- **Control plane:** incidents, baselines, learned rules, notifications, inventory and optional LLM analysis. It may be slow and wrong, and it cannot weaken enforcement.
- **One-way contract:** the control plane may send only restricting commands to the gate (pause run, revoke identity, quarantine tool, isolate agent). It cannot approve a call or relax a rule.
- LLMs, when used, run sandboxed with no network egress, read untrusted text as data, and write only suggestions that a human or a deterministic rule accepts.
- Decoy responses come from templates first. A small local model may fill rare gaps later; it never touches decisions.

## Consequences

- Easier to test and to reason about: the data plane has no model to jailbreak.
- Some detections (for example, nuanced prompt-injection classification) become hints that raise an incident, not blocks. That is intended.
