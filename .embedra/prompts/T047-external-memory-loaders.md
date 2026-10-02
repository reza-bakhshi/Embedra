# T047 Handoff Command — STM32 external-memory loaders and OCTOSPI/FMC mapping

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T047** from
`Embedra-SpecKit.md`:

> T047 Implement external-memory loaders and OCTOSPI/FMC mapping through
> confirmed board/device profiles.

Do **not** begin T048. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The T046 working tree is uncommitted (baseline commit `f356879` plus the
  T038-T046 work); `git status --porcelain` is not clean by design. Do not
  commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
  pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state.
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- Pinned snapshots that must not change: curated catalog
  (`afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`),
  memory plans (`00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`),
  SVD applicability (`be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518`),
  security domains (`08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9`),
  board profiles (`catalogs/stm32/2026-09-29/board-profiles.json`,
  `78a3e0e41cc14585ad3c4140aed80fff6d53fcd367d6beec3d2cc787950c75f3`),
  the F1 signature pack, and `packs/stm32.*.svd`.
- Local toolchain for every gate below: `JAVA_HOME=` `/usr/lib/jvm/java-21-openjdk-amd64`
  and `GHIDRA_INSTALL_DIR=` `ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`
  (both relative to the repository, JDK 21.0.12, Ghidra 12.1.3 PUBLIC).
- T039-T046 checkboxes are checked; `state.nextTask` is T047 and the T047 line
  is unchecked.
- Current repository verification baseline (T046 final gate): 341 unit, 93
  real-Ghidra, 131 STM32 Python (4 documented optional-source skips), and 4 ESP
  Python tests; two clean, uncached 22-action builds; byte-identical
  4,335,725-byte ZIP SHA-256
  `462d3ddc99378a5ec7ef7fadf3892b413e6f4d02efcc2adb60f701c95c2bf364`
  (`T046_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T046.md`
2. `.embedra/evidence/tasks/T045.md`, `T044.md`, `T043.md`, `T042.md`,
   `T041.md`, `T040.md`, `T039.md`
3. `Embedra-SpecKit.md` (STM-009, STM-016, STM-017, STM-019, STM-020,
   TOPO-001..006, and T047)
4. Existing code: `targets/stm32/board` (T042 `Stm32BoardCatalog`/
   `Stm32BoardPlanner`, `ExternalRegion`, boot offsets), `targets/stm32/memory`
   (plan regions and aliases), `targets/stm32/workspace` and
   `targets/stm32/wireless` (composition contracts), `ghidra/stm32`
   applicator patterns, and `core/model/*`.

Known baseline facts (do not re-derive by guesswork):

- T042's digest-pinned board snapshot
  (`catalogs/stm32/2026-09-29/board-profiles.json`, SHA-256
  `78a3e0e4…`, pinned board-index `2b9c7c2c…`, source audit
  `.embedra/evidence/tasks/T042-board-source-audit.json`) has nine reviewed
  profiles with pinned external flash/RAM facts: STM32H735G-DK/H735IGK6
  (MX25LM51245G 64 MiB @0x90000000 + S70KL1281 16 MiB @0x70000000),
  STM32H750B-DK/H750XBH6 (MT25TL01G 128 MiB @0x90000000 + IS42S32400F 16 MiB
  @0xD0000000), STM32H7S78-DK/H7S7L8H6H (MX66UW1G45G 128 MiB @0x70000000 +
  APS256XX 32 MiB @0x90000000), STM32H573I-DK/H573IIK3Q, STM32H5F5J-DK/
  H5F5LJH7Q, STM32L562E-DK/L562QEI6Q (NOR only), B-U585I-IOT02A/U585AII6Q,
  STM32U5G9J-DK1/U5G9NJH6Q, and STM32N6570-DK/N657X0H3Q. Three parts have
  exact board evidence but no pinnable external fact and stay explicitly
  unavailable with pinned reasons: `STM32G473QET6`
  (`NO_PINNED_BSP_EXTERNAL_MEMORY_FACT`), `STM32U083MCT6`
  (`BOARD_HAS_NO_EXTERNAL_MEMORY_IN_PINNED_BSP`), `STM32L552ZET6Q`
  (`BOTH_EXTERNAL_DEVICES_SHARE_OCTOSPI1_MAPPED_WINDOW`).
- T042's `ExternalRegion` records device, controller, CPU start, size,
  writability, and quoted BSP start/size evidence in a distinct `ext-mem`
  address space that must never be confused with CPU addresses, while true
  numeric collisions still fail closed; `Stm32BoardPlanner.compose` is pure,
  never maps memory, and fails closed with `BOARD_*` diagnostics on an
  unavailable profile, a part mismatch, an overlapping or out-of-space
  external region, or a boot offset outside every external region. T047's
  loaders/mapping may use a real Ghidra adapter ONLY when actually tested
  under the adapter rules below.
- OCTOSPI/FMC controller windows are windowed apertures of the MCU, not board
  data; a board profile supplies the device, controller, start, size, and
  writability with pinned provenance. Any loader must fail closed when an
  input is absent, truncated, unconfirmed, or out of profile, and must never
  invent a controller, window, alias, or permission.
- STM-016: custom board profiles add external flash/RAM and boot offsets
  without changing the underlying MCU pack; T047 must keep that separation.
- The `ext-mem` space, the T042 artifact, and its generator/tests are pinned
  and must not mutate; additive extension requires its own deterministic
  generator and digest contract if a new snapshot is added.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: loaders/mapping planning stay under
  `targets`; any Ghidra mutation stays under `ghidra` inside one
  rollback-capable transaction, idempotent, preserving user artifacts and
  never resurrecting deleted or renamed ones, bound to the program-recorded
  exact part (fail closed on disagreement).
- Do not modify T039-T046 artifacts or promote any support state (STM-019).
- Never invent an external device, controller window, alias, size, permission,
  board link, or address. Every mapping originates from a confirmed
  profile/user input plus pinned evidence, failing closed otherwise.
- Reuse `ParserLimits`, `CancellationToken`, `AddressRange`, the T042
  board-profile contracts, the T039 plan contracts, and the existing exact-part
  digest-pinned catalog contracts.
- Apply the review lessons: typed diagnostics for out-of-range values,
  constructors that reject overlapping/duplicate/ambiguous records, and
  exact-part binding for any Ghidra adapter.

## 2. Implement

1. **External-memory loading plan**: a pure planner that turns a confirmed
   board (or custom) profile plus the T039 MCU plan into an external-memory
   mapping plan (device, controller, window, size, writability, evidence),
   with explicit unavailability otherwise.
2. **OCTOSPI/FMC mapping**: model the controller window/aperture separation
   from the pinned board and MCU data only; no invented window or alias.
3. **Optional Ghidra adapter**: only if real-Ghidra tested (transaction, idempotence,
   preservation, non-resurrection, ambiguous no-op, exact-part binding).
   If none is added, record `NO_ADAPTER_PURE_PLAN_ONLY`.
4. **Custom profiles**: accept confirmed user-supplied profiles without
   mutating any pinned snapshot, rejecting overlaps with pinned MCU regions
   and fabricated controller data.
5. **Docs**: update `docs/architecture.md` and `docs/support-matrix.md`,
   plus `THIRD_PARTY_NOTICES.md` only if new redistributable material is
   described.

## 3. Tests (test-first, meaningful)

- Pure unit tests: plan composition over the pinned T042 profiles, mapping
  windows and disjointness, explicit unavailability, immutability, part
  binding, fail-closed configuration inputs.
- Boundary tests: truncated/oversized/duplicate/out-of-range/unknown/tamper
  paths (and generator/snapshot tests only if a new snapshot is added).
- Real-Ghidra integration tests only if an adapter is added.
- Keep the STM32/ESP Python suites green; record every optional-source skip
  exactly.

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

- Add `.embedra/evidence/tasks/T047.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T047`,
  real exit status, result, artifacts).
- Update `.embedra/state.json` with a T047 section, check T047 complete, add it
  to `completedTasks`, set `nextTask` to T048 and the matching unchecked
  SpecKit task, update test counts, working tree, and artifacts with the new
  ZIP digest.
- Check the T047 box in `Embedra-SpecKit.md` and update the spec digest in
  state.
- Update `PROJECT_STATE.md` and write the next handoff prompt
  `.embedra/prompts/T048-*.md`.
- Do not modify T039-T046 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for an external-memory or controller source, the only available
links are family or wildcard inference, or implementing T047 would require
mutating T039-T046 data. The prompt is also referenced by
state.evidence.nextTaskPrompt, so the next session picks it up automatically.
