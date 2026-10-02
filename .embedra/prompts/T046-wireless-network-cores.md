# T046 Handoff Command — WB/WB0/WL/WBA wireless and network-core distinctions

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T046** from
`Embedra-SpecKit.md`:

> T046 Implement WB/WB0/WL/WBA wireless/network-core distinctions, separately
> supplied coprocessor firmware, shared resources, and related packs.

Do **not** begin T047. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The T045 working tree is uncommitted (baseline commit `f356879` plus the
  T038-T045 work); `git status --porcelain` is not clean by design. Do not
  commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
  pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state.
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- Pinned snapshots that must not change: curated catalog
  `catalogs/stm32/2026-09-29/curated-catalog.json`
  (`afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`),
  memory plans `00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`,
  SVD applicability
  `be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518`,
  security domains `08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9`,
  board profiles, F1 signature pack, and `packs/stm32.*.svd`.
- T044, T045, T043, T042, T041, T040, and T039 checkboxes are checked;
  `state.nextTask` is T046 and the T046 line is unchecked.
- Current repository verification baseline (T045 final gate): 331 unit, 93
  real-Ghidra, 131 STM32 Python (4 documented optional-source skips), and 4 ESP
  Python tests; two clean, uncached 22-action builds; byte-identical
  4,294,974-byte ZIP SHA-256
  `6ad9a71f94f5af9a0cd9777fd2f2e9b7dc385bde9958b77c2cf2a70265fa6133`
  (`T045_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T045.md`
2. `.embedra/evidence/tasks/T044.md`, `T043.md`, `T042.md`, `T041.md`,
   `T040.md`, `T039.md`
3. `.embedra/evidence/tasks/T039-T041-hardening.md` and
   `.embedra/evidence/tasks/T038-T041-followup-review.md`
4. `Embedra-SpecKit.md` (STM-008, STM-009, STM-011, STM-014, STM-019, STM-020,
   TOPO-001..006, and T046)
5. Existing code: `targets/stm32/workspace` (T045 `Stm32WorkspacePlanner`
   segments and cross-program references), `targets/stm32/memory`
   (`WB_DUAL_CORE`, `WB0_SINGLE_CORE`, `WL3_SINGLE_CORE`, `WBA_SINGLE_CORE`
   profiles), `targets/stm32/security` (composition contract), `core/model/*`,
   and the `ghidra/stm32` applicator patterns.

Known baseline facts (do not re-derive by guesswork):

- All 53 curated parts are `PLANNED`. The curated WB scope is exactly
  `STM32WB55RGV6`, `STM32WB15CCU6` (WB_DUAL_CORE), `STM32WB05KZV6TR`,
  `STM32WB07CCV6TR`, `STM32WB09KEV6TR` (WB0 single core), and
  `STM32WBA25CEU7`, `STM32WBA52CGU6`, `STM32WBA65RIV7` (WBA single core);
  the WL scope is `STM32WL33CCV6TR` and `STM32WL3RKBV6` (WL3 single core).
- T045 plans only the two WB_DUAL_CORE parts as multi-core workspaces
  (`MULTI_CORE_PINNED`); WB0/WL3/WBA are single-core for the pinned executable
  CPU firmware and stay `UNAVAILABLE` with the recorded
  `SINGLE_CORE_EXECUTION_TOPOLOGY` reason. T045 does not touch radios.
- CPU2 images of WB55/WB15 are independently supplied and unstated; T046 may
  only model separately supplied coprocessor firmware that pinned sources fix
  (import contract, format, address binding); absent facts stay explicit
  `UNAVAILABLE` with a reason.
- Every curated catalog record, support state, memory/topology fact, and
  T042-T044 artifact is pinned and owned by T032/T038-T044; T045 is the owner
  of workspace facts and must not be mutated for T046 without good reason and
  additive design.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: wireless/network-core modeling, coprocessor
  firmware sourcing, shared-resource ownership, and packs stay under
  `targets`/`analyzers`/`pack`; Ghidra mutation stays under `ghidra`. Do not
  import Ghidra APIs into pure packages.
- STM-014/STM-020/TOPO-005: distinguish physical CPU cores, network/radio
  cores, programmable coprocessors, DMA/bus masters, fixed-function
  accelerators, and radio hardware. Only units executing recoverable
  instructions are disassembled; radio hardware is never modeled as firmware.
- Never invent a wireless protocol state, radio register map, CPU2 image
  range, or T039-T045 artifact. No family, sibling, or wildcard inference;
  every link is exact-part.
- STM-019: no exact part support state is promoted by T046.
- Any new snapshot must be generated deterministically from pinned,
  license-reviewed inputs with per-file digests, be digest-checked by its
  loader, and add its ZIP-entry oracle rows; no vendor bytes are
  redistributed beyond reviewed licenses.
- Reuse `ParserLimits`, `CancellationToken`, `ProcessorNode`,
  `ExecutionTopology`, `SharedMemoryRegion`, `InterProcessorLink`,
  `BootRelationship`, the `Stm32WorkspacePlanner` cross-program contract, and
  the existing exact-part digest-pinned catalog contracts.
- Apply the review lessons: typed diagnostics for out-of-range values,
  constructors that reject overlapping/duplicate/ambiguous records, and
  exact-part binding for any Ghidra adapter.

## 2. Implement

1. **Wireless/network-core model**: per-exact-part records for the WB/WB0/WL3/
   WBA scopes that distinguish the executable network processor (WB55/WB15
   CPU2), the radio hardware of WB0/WL parts, and the WBA radio/secure
   hardware, from pinned evidence only.
2. **Separately supplied coprocessor firmware**: model the sourcing contract
   for CPU2 firmware (format, address binding, part binding) only where pinned
   sources fix it; everything else stays explicit.
3. **Shared resources and packs**: attribute shared resources across cores
   (SRAM1, IPCC, HSEM, RF workspace) without duplicating them, and add a
   device-data pack only if a pinned, license-reviewed source ships it.
4. **Optional Ghidra adapter**: only if real-Ghidra tested with transactional
   apply, rollback, idempotence, preservation, and non-resurrection, bound to
   the program-recorded exact part. If none is added, record
   `NO_ADAPTER_PURE_PLAN_ONLY` explicitly.
5. **Docs**: update `docs/architecture.md`, `docs/support-matrix.md`, and
   `THIRD_PARTY_NOTICES.md` only if new redistributable material is described.

## 3. Tests (test-first, meaningful)

- Pure unit tests: per-exact-part applicability and explicit unavailability,
  exact-part binding, immutability of T039-T045 artifacts, resolution
  strictness, shared-resource attribution, diagnostics.
- Boundary tests: truncated/oversized/duplicate/out-of-range/unknown/tamper
  paths per loader.
- Generator tests if a snapshot is added: deterministic regeneration, tamper
  rejection, pinned-source hash checks.
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

- Add `.embedra/evidence/tasks/T046.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T046`,
  real exit status, result, artifacts).
- Update `.embedra/state.json` with a T046 section, check T046 complete, add it
  to `completedTasks`, set `nextTask` to T047 and the matching unchecked
  SpecKit task, update test counts, working tree, and artifacts with the new
  ZIP digest.
- Check the T046 box in `Embedra-SpecKit.md` and update the spec digest in
  state.
- Update `PROJECT_STATE.md` and write the next handoff prompt
  `.embedra/prompts/T047-*.md`.
- Do not modify T039-T045 evidence, artifacts, or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for a wireless/network-core source, the only available links are
family or wildcard inference, or implementing T046 would require mutating
T039-T045 data. The prompt is also referenced by state.evidence.nextTaskPrompt,
so the next session picks it up automatically.
