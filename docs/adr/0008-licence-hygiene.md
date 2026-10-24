# ADR-0008: Licence hygiene; clean-room tokens

Status: Accepted (owner approval, 24 October 2026). Date: 2026-10-24.

## Context

Thinkst Canarytokens is GPL v3 with extra terms that treat integrating, linking to or executing its code as creating a derivative work, and Thinkst sells alternative licences (`LICENSE` in `thinkst/canarytokens`). Our code is Apache-2.0.

## Decision

- Do not copy, link or execute code from Canarytokens or any similarly licensed project.
- Generate our own token formats from public format knowledge (for example, the documented shape of an API key), with an embedded registry id, and write them from scratch.
- Ideas, public documentation and behaviour may inform design. Record them in the pull request.
- Any new dependency must be Apache-2.0, MIT, BSD or ISC unless the owner approves otherwise. CI should run a licence check (backlog E0-4).

## Consequences

- Slightly more work for F6. No licence risk for adopters.
