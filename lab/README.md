# Lab

Test targets and scenarios for Project Honeycomb. Everything here is synthetic and runs on the
local machine only.

- `targets/crm.py`: a toy CRM over generated customers. `export_report` records every call, so a
  scenario can prove whether a real export happened.
- `targets/docs.py`: a document store with one poisoned document (a harmless stand-in).
- `scenarios/s1_poisoned_doc.py`: the scripted attacker for scenario S1. It's a plain script with
  no model, and it refuses to start anything that isn't a local lab target.

Run the scenario through the tests: `uv run pytest gate/tests/test_scenario_s1.py -q`.
The Docker Compose version, with an internal-only network and the egress proxy, comes with M3.
