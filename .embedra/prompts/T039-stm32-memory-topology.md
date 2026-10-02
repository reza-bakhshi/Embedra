Work in `/home/rez0x61/Projects/ghidra_extension`. T039 is complete after two
correctness reviews; T033–T038 are complete. Read `.embedra/state.json` and
`.embedra/evidence/tasks/T039.md` first. Do not print full catalogs,
specification, or memory snapshots.

All 53 selected exact parts have validated pure memory/topology plans in the
additive `catalogs/stm32/2026-09-29/memory-plans.json` (SHA-256
`00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`, root status
`COMPLETE_T039`, 53 `VALIDATED_MAP` records, 88 source documents). The original
curated catalog is unchanged and every part stays `PLANNED`.
`python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0.

Corrections applied across the two reviews:
- WB15 (`STM32WB15CCU6`) is a genuine dual-core part (Cortex-M4 CPU1 +
  Cortex-M0+ CPU2, IPCC/HSEM) and uses profile `WB_DUAL_CORE`.
- H735's 192-KiB shared RAM resolves the four TCM_AXI_SHARED allocations to
  concrete ITCM/AXI ranges and is placed only when an explicit allocation ID is
  supplied; otherwise it is reported as unresolved.
- WB55/WB15 `SharedMemoryRegion` access is data-driven; dual-core RAM requires
  explicit `sharedAccess` metadata and the planner no longer has an
  unrestricted-sharing fallback.
- The readiness audit rejects missing dual-core IPCC/HSEM ranges (malformed or
  unordered bounds), profile/core-count mismatches, invalid availability values,
  undeclared configuration markers, malformed or size-mismatched allocation
  definitions, and missing/invalid shared access.

Verification: the reproducible gate passes with two clean 22-action builds;
237 unit, 75 real-Ghidra, 94 STM32 Python, and 4 ESP Python tests. The STM32
Python suite intentionally reports `OK (skipped=2)`: two checks require the
optional pinned ST source downloads, which are absent in a clean checkout, so
"zero skips" is not claimed. The byte-identical ZIP SHA-256 is recorded in
`state.json`.

Next: T040 (CMSIS-SVD/device-data transformation with provenance).
