# T041 Handoff Command — STM32 vector labels/functions and Cortex-M core exceptions

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T041** from
`Embedra-SpecKit.md`:

> T041 Implement vector labels/functions and Cortex-M core exception structures.

Do **not** begin T042. Do not commit, push, or publish unless explicitly asked.

## 0. Read and validate first (stop on any mismatch)

Read, in order:

1. `.embedra/state.json`
2. `.embedra/evidence/tasks/T040.md`
3. `.embedra/evidence/tasks/T039.md` and `.embedra/evidence/tasks/T037.md`
4. `Embedra-SpecKit.md` (STM-003, STM-006, STM-007, STM-019 and T041)
5. Existing vector/catalog/adapter code (class names; locate under `src/main/java`):
   `Stm32VectorDiscovery`, `Stm32VectorApplicator`,
   `Stm32DevicePackRegistry`, `Stm32InterruptPlan`, `Stm32SvdApplicator`,
   and their tests under `src/test`/`src/integrationTest`.

Verify before writing code:

- `sh scripts/validate-handoff.sh` and `sh scripts/validate-fixture-provenance.sh` pass.
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0 with `readyCount 53/53`.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state.
- T040 applicability digest is `be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518`.
- Record the final T040 reproducible ZIP digest `f04ee66e34f9e942ac5728a50eb1f1bd0d45faeff1c63faf1d82342f5daeb004`; if the tree differs, re-run the gate before relying on it.

If anything disagrees, report the discrepancy and stop instead of guessing.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: detection, planning, and validation stay under
  `core`/`targets`; Ghidra mutation stays under `ghidra`.
- T039 memory plans (`catalogs/stm32/2026-09-29/memory-plans.json`), the T040
  device-data packs, the applicability artifact, and the WB15/WB55 non-secure
  SRAM2 limitation are unchanged.
- Every device-support state remains `PLANNED`. Do not promote support because a
  label or function was created.
- Never invent vector addresses, handler names, interrupt numbers, or exact-part
  compatibility. Family and wildcard inference stay forbidden.
- Preserve user symbols, functions, data, instructions, and comments; make
  repeated application idempotent and transactional (rollback unless explicit
  commit).
- Distinguish Cortex-M core exceptions from device IRQs. Do not create functions
  for unconfirmed or ambiguous vector tables; fail closed.

## 2. Implement

1. **Pure vector/core-exception model.** Build on T037's explicit candidate
   selection and T039 RAM ranges. Represent the exact-part interrupt list from
   `Stm32InterruptPlan` and a separate, explicit core-exception table
   (`NonMaskableInt`, `HardFault`, `MemManage`, `BusFault`, `UsageFault`,
   `SVCall`, `DebugMonitor`, `PendSV`, `SysTick`), preserving unknown entries
   rather than fabricating them. Resolve handler addresses from the confirmed
   image base and vector slot only when the table is confirmed.
2. **Name/label resolution.** Derive handler names from the exact part's pinned
   interrupt names and core exceptions. Keep naming deterministic and qualified;
   preserve any existing name and record a conflict instead of overwriting.
3. **Ghidra adapter.** Inside one rollback-capable transaction: create/confirm
   vector labels, create functions for confirmed reset/handler slots, apply core
   exception structures, and record provenance (exact part, source digest,
   confirmation method, created/conflicted counts). Reapplication must be
   idempotent and must not resurrect deleted or user-modified artifacts.
4. **Ambiguity handling.** If the vector table is unconfirmed, the base is
   unknown, or the interrupt list is conditional/variant-dependent, emit an
   explicit diagnostic and apply nothing. Do not infer from a family.

## 3. Tests (test-first, meaningful)

- Pure unit tests: core-exception table, handler-name resolution, slot/address
  math, unknown/ambiguous rejection, unresolved handler addresses, idempotence.
- Malformed/boundary tests: truncated tables, unaligned/overlapping slots,
  out-of-range vectors, missing interrupt list.
- Representative real-Ghidra integration tests: labels/functions created for a
  confirmed table; user symbol/function/data preservation; conflict reporting;
  repeated apply creates nothing new; ambiguous table creates nothing.
- Keep the STM32 Python suite green; if a generator changes, add/extend its tests
  and record any optional-source skips accurately.

## 4. Acceptance gates (run and record actual output)

1. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew check verifyFormatting --no-daemon`
2. `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'`
3. `python3 -m unittest scripts/tests/test_generate_esp_catalog.py`
4. `python3 scripts/audit-stm32-memory-readiness.py --require-complete`
5. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> scripts/verify-build-quality.sh`
   (must report two clean, uncached 22-action builds and a byte-identical ZIP)
6. `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`

Compilation alone is not verification. If a test fails, is skipped, or an
optional source is absent, record it exactly.

## 5. Evidence and continuity

- Add `.embedra/evidence/tasks/T041.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T041`,
  real exit status, result, artifacts).
- Update `.embedra/state.json`: check T041 complete, add to `completedTasks`,
  set `nextTask` to T042 and the matching unchecked SpecKit task, update test
  counts, working tree, and artifacts with the new ZIP digest.
- Check the T041 box in `Embedra-SpecKit.md` and update the spec digest in state.
- Update `PROJECT_STATE.md` and the next handoff prompt
  `.embedra/prompts/T042-*.md`.
- Do not modify T039/T040 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for a vector/core-exception source, or implementing T041 would
require mutating T039/T040 data or guessing exact-part compatibility.
