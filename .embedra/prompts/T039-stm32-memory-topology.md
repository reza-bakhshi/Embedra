# New chat — continue T039

Work in `/home/rez0x61/Projects/ghidra_extension`. Continue T039 from
`Embedra-SpecKit.md`; T033–T038 are complete. Read `.embedra/state.json` and
`.embedra/evidence/tasks/T039.md` first. Inspect only the relevant SpecKit
section and candidate records as needed; do not print the full specification,
catalog, or `T039-memory-candidates.json` into chat context.

T039 has 53 selected STM32 parts, all `PLANNED`. Pinned DFP candidates cover
50; three F103 parts need separate address reconciliation. Resolve physical
banks, aliases, capacity conflicts, seven shorter DFP name matches, and
system/OTP/option applicability using pinned authoritative evidence. Query
`T039-memory-candidates.json`, `T039-dfp-source-audit.json`, and
`T039-f103-source-audit.json` by exact part when useful. Keep unknown facts
unknown. Implement pure topology planning and meaningful representative tests
only after the evidence supports each map. Update T039 evidence and state.

Use JDK 21 and the local Ghidra 12.1.3 path recorded in project state. Run
focused tests while iterating and the full reproducible gate when T039 is
ready. `scripts/audit-stm32-memory-readiness.py --require-complete` currently
fails by design: no validated bank maps. Keep T039 unchecked until it passes.
