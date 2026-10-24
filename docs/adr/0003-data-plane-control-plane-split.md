# ADR-0003: Deterministic data plane, separate control plane

Status: Accepted by the owner on 24 October 2026. Date: 2026-10-24.

## Context

Any enforcement decision made by a language model can be prompt-injected, and model latency is the most cited honeypot giveaway (see [HARD-PROBLEMS.md](../HARD-PROBLEMS.md), problems 3 and 5).

## Decision

We split the system in two.

The data plane is the gate. It is deterministic code only: rules, hashes, token checks, pattern scans and caps. It answers in milliseconds and fails closed for high-impact tools.

The control plane handles incidents, baselines, learned rules, notifications, inventory and optional LLM analysis. It may be slow and it may be wrong, but it cannot weaken enforcement. The contract between the two is one-way: the control plane may send the gate only restricting commands (pause run, revoke identity, quarantine tool, isolate agent). It cannot approve a call or relax a rule.

When LLMs are used, they run sandboxed with no network egress and read untrusted text as data. They write only suggestions, which a human or a deterministic rule must accept. Decoy responses come from templates first. A small local model may fill rare gaps later, but it never touches decisions.

## Consequences

The data plane is easier to test and reason about, because there is no model in it to jailbreak.

Some detections, such as nuanced prompt-injection classification, become hints that raise an incident rather than blocks. That is intended.
