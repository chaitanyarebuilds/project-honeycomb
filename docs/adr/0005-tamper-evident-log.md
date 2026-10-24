# ADR-0005: Hash-chained event log from M1

Status: Accepted by the owner on 24 October 2026. Date: 2026-10-24.

## Decision

Each event stores `prev_hash` and `hash` (SHA-256 over the canonical JSON of the event plus the previous hash). `honeycomb-gate events verify` recomputes the chain and reports the first break. Critical events are also sent to a second sink (a webhook or a separate file path) that the agent's account cannot write to. Chain heads are written to that second sink periodically, so truncation is detectable.

## Why

An attacker who is already inside edits the logs first. A chain doesn't stop deletion, but it makes tampering visible, which is the property CERT-In asks for ("tamper-resistant agent-action logs").

## Consequences

The schema gains two small fields (`prev_hash`, `hash`), and we're adding them while schema v1 is unreleased. We also need rotation and retention rules (backlog item E1-5).
