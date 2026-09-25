# T030 Handoff Prompt — Remaining ESP Providers

Implement only T030 from `Embedra-SpecKit.md`. Add each listed ESP target as an
independent provider with exact maintained identity, architecture, processor
roles/counts, memory and entry rules, ROM/peripheral evidence, redistributable
fixtures, and real-Ghidra coverage. Include newer official series only when the
T026 catalog evidence requires them. Do not infer support from family names or
reuse another target's fixture as proof.

Start by validating `PROJECT_STATE.md`, `.embedra/state.json`, the specification
digest, clean Git state, and `.embedra/evidence/tasks/T029.md`. Preserve all
ESP32, ESP32-S2, ESP32-S3, and ESP32-C3 regressions, the ISA-neutral common-code
boundary, exact package oracle, and default-off enrichment policy. Finish with
the complete quality and reproducibility gates and a reviewable continuity
handoff; do not start T031.
