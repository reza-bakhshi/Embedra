# T029 Handoff Prompt — ESP32-C3 RISC-V Provider

Implement only T029 from `Embedra-SpecKit.md`: add ESP32-C3 as the first
RISC-V ESP provider and prove that shared ESP code contains no Xtensa
assumptions. Do not begin T030.

Start by validating `PROJECT_STATE.md`, `.embedra/state.json`, the specification
digest, the clean Git state, and `.embedra/evidence/tasks/T028.md`. Use pinned,
redistributable primary sources and a test-first workflow. Add an independent
ESP32-C3 fixture, maintained chip identity, provider-owned memory and topology,
the correct Ghidra RISC-V language/compiler pair, target-specific packs, and
raw plus explicitly enriched real-Ghidra import coverage. Preserve all existing
ESP32, ESP32-S2, and ESP32-S3 regressions and the exact package-content oracle.

Finish only after the complete quality and reproducibility gates pass, then
record T029 evidence and continuity state without promoting any unverified
catalog target or claiming exact package, board, ULP, or hardware coverage.
