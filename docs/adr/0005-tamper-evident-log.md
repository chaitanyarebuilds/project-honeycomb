# ADR-0005: Hash-chained event log from M1

Status: Accepted (owner approval, 24 October 2026). Date: 2026-10-24.

## Decision

Each event stores `prev_hash` and `hash` (SHA-256 over the canonical JSON of the event plus the previous hash). `honeycomb-gate events verify` recomputes the chain and reports the first break. Critical events are also sent to a second sink (webhook or separate file path) that the agent's account cannot write to. Chain heads are periodically written to that second sink so truncation is detectable.

## Why

An attacker already inside edits logs first. A chain does not stop deletion, but it makes tampering visible, which is the property CERT-In asks for ("tamper-resistant agent-action logs").

## Consequences

- Small schema addition (`prev_hash`, `hash`), made while schema v1 is unreleased.
- Rotation and retention rules needed (backlog item E1-5).
