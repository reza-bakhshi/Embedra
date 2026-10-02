# T045 Handoff Command — STM32 dual-core/heterogeneous workspace planning

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T045** from
`Embedra-SpecKit.md`:

> T045 Implement dual-core/heterogeneous workspace planning, shared memory,
> mailboxes/semaphores, boot relationships, and cross-program navigation for
> every applicable H7 and other cataloged multi-core device.

Do **not** begin T046. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The T044 working tree is uncommitted (baseline commit `f356879` plus the
  T038–T044 work); `git status --porcelain` is not clean by design. Do not
  commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
  pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state
  (T044 changed it to `62f729e82be4c7adef3869dc7bb338a1ae569a8488f1be2298ee3108936e786a`).
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- T044 snapshot SHA-256
  `08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9`;
  curated catalog `afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`;
  memory plans `00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`;
  SVD applicability `be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518`.
- T044 is checked in `Embedra-SpecKit.md`, `state.nextTask` is T045, and the
  T045 line is unchecked.
- Current repository verification baseline (T044 final gate): 316 unit, 93
  real-Ghidra, 131 STM32 Python (4 documented optional-source skips), and 4 ESP
  Python tests; two clean, uncached 22-action builds; byte-identical
  4,256,466-byte ZIP SHA-256
  `9b3ab2e3577786a6b37f39d038eec16d5c0b7b71375c48ecc8a7f2f1d3e623f6`
  (`T044_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T044.md`
2. `.embedra/evidence/tasks/T043.md`, `T042.md`, `T041.md`, `T040.md`, `T039.md`
3. `.embedra/evidence/tasks/T039-T041-hardening.md`,
   `.embedra/evidence/tasks/T038-T041-followup-review.md`
4. `Embedra-SpecKit.md` (STM-009, STM-011, STM-019, STM-020, TOPO-001..006, and
   T045)
5. Existing topology/workspace code: `targets/stm32/memory/Stm32MemoryPlanner`
   (especially `dualCoreTopology`, `SharedMemoryRegion`, `InterProcessorLink`,
   `BootRelationship`, and the `WB_DUAL_CORE` profile), `targets/stm32/security`,
   `targets/stm32/vector`, `core/model/*`, and the `ghidra/stm32` applicator
   patterns.

Known baseline facts (do not re-derive by guesswork):

- All 53 curated parts are `PLANNED` and every support state stays unchanged.
- The curated scope has **exactly two pinned multi-core devices**:
  `STM32WB55RGV6` and `STM32WB15CCU6` (Cortex-M4 + Cortex-M0+). T039 already
  plans them with profile `WB_DUAL_CORE`, two `CPU_CORE` nodes, shared
  SRAM1/SRAM2A/SRAM2B, IPCC (`0x58000C00`), HSEM (`0x58001400`), a
  `RELEASES_FROM_RESET` relationship, and CPU2-only `sharedAccess` on SRAM2A/2B.
  T039 also records `secondaryCore`, `secondaryInstructionSet`,
  `secondaryLanguageId`, `secondaryCompilerSpecId`, and
  `secondaryBootMechanism` in those plans.
- Every curated H7 part (`STM32H735IGK6`, `STM32H750XBH6`, `STM32H7S3L8H6`,
  `STM32H7S7L8H6H`) is a single Cortex-M7 device. No dual-core H7 (for example
  H745/H755) is in the curated 53, and N6/WL3/WB0/WBA are single-core for
  executable CPU firmware. Missing second cores and missing coprocessor images
  must stay explicit `UNAVAILABLE` with a reason, never inferred from a family
  label or sibling part.
- T044's `Stm32SecurityPlanner.SecurityMap` already exposes security regions and
  veneer transitions purely; T039 remains the owner of memory/topology facts.
  Neither may be mutated.
- Pinned artifacts that must not change: `curated-catalog.json`,
  `memory-plans.json`, `svd-applicability.json` and `packs/stm32.*.svd`,
  `security-domains.json`, `board-profiles.json`, and
  `packs/stm32.stm32f1.signatures`.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: workspace planning, shared-resource
  attribution, mailbox/semaphore ranges, and boot relationships stay under
  `targets`/`analyzers`; Ghidra mutation stays under `ghidra`. Do not import
  Ghidra APIs into pure packages.
- STM-011/TOPO-004: represent dual-core/heterogeneous devices with separate
  core ownership and explicit cross-program relationships; create separate
  programs only when ISAs, images, or security domains would make one program
  misleading, and never invent a second flash image or duplicate physical RAM.
- STM-019: no exact part per-input-format/feature support state is promoted by
  T045.
- STM-020: model all applicable cores, boot relationships, shared memories,
  mailboxes, and semaphores only from pinned evidence; unavailable facts stay
  explicit and fail closed with a reason.
- Do not modify the curated catalog, T039–T044 artifacts, or any support state.
- Never invent a core, image, address range, mailbox, semaphore, boot order, or
  cross-program reference. No family or wildcard inference.
- Reuse `ParserLimits`, `CancellationToken`, `ProcessorNode`,
  `ExecutionTopology`, `SharedMemoryRegion`, `InterProcessorLink`,
  `BootRelationship`, and the existing exact-part digest-pinned catalog
  contracts.
- Apply the review lessons: typed diagnostics for out-of-range values,
  constructors that reject overlapping/duplicate/ambiguous records, and
  exact-part binding for any Ghidra adapter.

## 2. Implement

1. **Pure workspace model** (`targets/stm32/workspace` or an equivalent name):
   immutable per-exact-part workspace plans that reference the validated T039
   plan and T044 security map without mutation: one program/image per
   independently supplied executable domain, explicit core roles, shared vs.
   private memory, mailboxes/semaphores, boot/reset relationships, and
   cross-program references with provenance. A part with no pinned second core
   or coprocessor image is `UNAVAILABLE` with a reason and no fabricated fact.
2. **Components and disjointness**: validate that program memory ranges,
   shared-memory mirrors, mailbox/semaphore ranges, and security domains do not
   collide except at documented shared ranges; reject duplicate/ambiguous
   cores, missing evidence, overlapping independent images, and mismatched
   exact parts.
3. **Mailboxes/semaphores and boot order**: reuse the T039 IPCC/HSEM ranges and
   the `RELEASES_FROM_RESET` relationship; add any further pinned multi-core
   evidence only if it exists, otherwise stay explicit.
4. **Optional Ghidra adapter**: only if real-Ghidra tested. If added, bind to
   the program-recorded exact part (fail closed on disagreement, as in
   `Stm32SvdApplicator`/`Stm32VectorLabelApplicator`), apply inside one
   rollback-capable transaction, be idempotent, preserve user artifacts, and
   never resurrect deleted/renamed artifacts. If none is added, record
   `NO_ADAPTER_PURE_PLAN_ONLY` explicitly in evidence, as T042/T044 did.
5. **Docs**: update `docs/architecture.md` and `docs/support-matrix.md`, plus
   `THIRD_PARTY_NOTICES.md` only if new redistributable material is described.

## 3. Tests (test-first, meaningful)

- Pure unit tests: workspace invariants, exact-part applicability and explicit
  unavailability, immutability vs. the T039 plan and T044 security map,
  duplicate/overlapping/ambiguous programs, shared-memory and mailboxes,
  boot-order relationships, cross-program references, and fail-closed
  configuration input.
- Boundary tests: truncated/oversized/duplicate/out-of-range/unknown records.
- Generator tests (if a snapshot is added): deterministic regeneration, tamper
  rejection, and pinned-source hash checks.
- Real-Ghidra integration tests only if an adapter is added (transactional
  apply, rollback, idempotence, preservation, non-resurrection, ambiguous
  no-op).
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

- Add `.embedra/evidence/tasks/T045.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T045`,
  real exit status, result, artifacts).
- Update `.embedra/state.json`: add an `stm32DualCoreWorkspace` (or equivalent)
  section, check T045 complete, add it to `completedTasks`, set `nextTask` to
  T046 and the matching unchecked SpecKit task, update test counts, working
  tree, and artifacts with the new ZIP digest.
- Check the T045 box in `Embedra-SpecKit.md` and update the spec digest in state.
- Update `PROJECT_STATE.md` and write the next handoff prompt
  `.embedra/prompts/T046-*.md`.
- Do not modify T039–T044 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for a workspace source, the only available links are family or
wildcard inference, or implementing T045 would require mutating T039–T044 data.
