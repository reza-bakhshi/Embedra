# T042 Handoff Command — STM32 board profiles for external memory and boot offsets

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T042** from
`Embedra-SpecKit.md`:

> T042 Add board profiles for external flash/RAM and boot offsets without mutating
> MCU packs.

Do **not** begin T043. Do not commit, push, or publish unless explicitly asked.

## 0. Read and validate first (stop on any mismatch)

Read, in order:

1. `.embedra/state.json`
2. `.embedra/evidence/tasks/T041.md`
3. `.embedra/evidence/tasks/T039.md` (memory plans) and `T040.md` (device data)
4. `Embedra-SpecKit.md` (STM-002, STM-005, STM-009, STM-016, STM-017 and T042)
5. Existing memory/catalog/loader code under `src/main/java`:
   `Stm32MemoryPlanner`, `Stm32DevicePackRegistry`, `Stm32RawBinPlan`,
   `Stm32RawBinImporter`, and existing board/catalog snapshots.

Verify before writing code:

- `sh scripts/validate-handoff.sh` and `sh scripts/validate-fixture-provenance.sh` pass.
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0 with `readyCount 53/53`.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state.
- Record the T041 reproducible ZIP digest and size from state; if the working tree
  differs, re-run `scripts/verify-build-quality.sh` before relying on it.

If anything disagrees, report the discrepancy and stop instead of guessing.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: board-profile parsing, planning, and validation
  stay under `core`/`targets`; Ghidra mutation stays under `ghidra`.
- Board profiles MUST NOT mutate or extend an MCU pack. External flash/RAM and
  boot offsets are additive board facts layered over an exact MCU record.
- T039 memory plans (`catalogs/stm32/2026-09-29/memory-plans.json`), T040
  device-data packs, the applicability artifact, T041 vector behavior, and the
  WB15/WB55 non-secure SRAM2 limitation are unchanged.
- Every device-support state remains `PLANNED`. A board profile never promotes
  MCU or board support, and never infers an exact part from a family or wildcard.
- Never invent an external memory size, address, boot offset, or board-to-MCU
  pairing. Unavailable or ambiguous facts stay explicit and fail closed.
- Preserve user symbols, functions, data, instructions, and comments; make
  repeated application idempotent and transactional (rollback unless explicit
  commit).

## 2. Implement

1. **Pure board-profile model.** Represent an exact board identity, its pinned
   external flash/RAM regions, and boot offsets separately from the MCU memory
   plan. Resolve a profile to an MCU only by an explicit exact-part link; unknown
   or ambiguous links fail closed. Keep physical board ranges distinct from CPU
   addresses and flash offsets where the format requires it.
2. **Plan composition.** Compose a validated MCU `Stm32MemoryPlanner.Plan` with a
   board profile without mutating the MCU regions, aliases, or topology. Reject
   overlapping external regions, invalid boot offsets, and unpaired or
   conflicting board facts with stable diagnostics.
3. **Catalog/provenance.** Add or extend a digest-pinned, redistributable board
   snapshot with source revision, license, and per-record provenance. Do not
   fabricate a board-to-part link that the pinned source does not state.
4. **Ghidra adapter.** Optionally map external memory/boot evidence transactionally
   behind explicit input, preserving all existing artifacts and remaining
   idempotent. If mapping external regions is out of scope for this task, keep the
   pure plan and document the boundary rather than guessing memory permissions.

## 3. Tests (test-first, meaningful)

- Pure unit tests: exact board/part resolution, external-region math, boot-offset
  bounds, overlap rejection, missing/ambiguous board facts, digest/provenance
  tampering, and immutability of the underlying MCU plan.
- Malformed/boundary tests: negative/overflowing offsets, zero-length or
  overlapping regions, unknown board IDs, duplicate records, and out-of-range
  addresses.
- Real-Ghidra integration tests if an adapter is added: preservation,
  idempotence, rollback, and no-mutation on ambiguity.
- Keep the STM32 Python suite green; if a generator or snapshot changes, add or
  extend its tests and record optional-source skips accurately.

## 4. Acceptance gates (run and record actual output)

1. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew check verifyFormatting --no-daemon`
2. `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'`
3. `python3 -m unittest scripts/tests/test_generate_esp_catalog.py`
4. `python3 scripts/audit-stm32-memory-readiness.py --require-complete`
5. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> scripts/verify-build-quality.sh`
   (two clean, uncached 22-action builds and a byte-identical ZIP)
6. `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`

Compilation alone is not verification. If a test fails, is skipped, or an
optional source is absent, record it exactly.

## 5. Evidence and continuity

- Add `.embedra/evidence/tasks/T042.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T042`,
  real exit status, result, artifacts).
- Update `.embedra/state.json`: check T042 complete, add to `completedTasks`, set
  `nextTask` to T043 and the matching unchecked SpecKit task, update test counts,
  working tree, and artifacts with the new ZIP digest.
- Check the T042 box in `Embedra-SpecKit.md` and update the spec digest in state.
- Update `PROJECT_STATE.md` and the next handoff prompt `.embedra/prompts/T043-*.md`.
- Do not modify T039/T040/T041 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for a board/external-memory source, the only available board-to-part
links are family or wildcard inference, or implementing T042 would require
mutating T039/T040/T041 data.
