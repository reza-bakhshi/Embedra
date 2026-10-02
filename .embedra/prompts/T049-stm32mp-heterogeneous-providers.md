# T049 Handoff Command — STM32MP/heterogeneous parts as distinct providers

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T049** from
`Embedra-SpecKit.md`:

> T049 Research and implement selected STM32MP/heterogeneous parts as distinct
> providers covering Cortex-A artifacts, Cortex-M firmware, boot chain, device
> tree, trusted/security domains, and shared resources without weakening MCU
> assumptions.

Do **not** begin T050. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The T048 working tree is uncommitted (baseline commit `f356879` plus the
  T038-T048 work); `git status --porcelain` is not clean by design. Do not
  commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
  pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state
  (`e16dcfa8d1d9216ba3d6d4669463b4346af0ddfc75fd690d15be9323662d979c`).
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- Pinned snapshots that must not change: curated catalog
  (`catalogs/stm32/2026-09-29/curated-catalog.json`,
  `afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`),
  memory plans (`memory-plans.json`,
  `00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`),
  SVD applicability (`svd-applicability.json`,
  `be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518`),
  security domains (`security-domains.json`,
  `08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9`),
  board profiles (`board-profiles.json`,
  `78a3e0e41cc14585ad3c4140aed80fff6d53fcd367d6beec3d2cc787950c75f3`), the F1
  signature pack (`packs/stm32.f1.signatures`), and `packs/stm32.*.svd`.
- Local toolchain for every gate below:
  `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64` and
  `GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`
  (JDK 21.0.12, Ghidra 12.1.3 PUBLIC).
- T039-T048 checkboxes are checked; `state.nextTask` is T049 and the T049 line
  is unchecked.
- Current repository verification baseline (T048 final gate): 378 unit, 104
  real-Ghidra, 131 STM32 Python (4 documented optional-source skips), and 4 ESP
  Python tests; two clean, uncached 22-action builds; byte-identical
  4,432,899-byte ZIP SHA-256
  `f530fbf952f89ca025b268a7f0d10c5c9138a718364b75b1d663006c4a82852d`
  (`T048_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T048.md`
2. `.embedra/evidence/tasks/T047.md`, `T046.md`, `T045.md`, `T044.md`,
   `T043.md`, `T042.md`, `T041.md`, `T040.md`, `T039.md`
3. `Embedra-SpecKit.md` (T049; STM-004, STM-008, STM-011, STM-015, STM-017,
   STM-019, STM-020, STM-021; TOPO-001..006; ADR 0026 for the STM32 source
   boundary; and the T032 source-snapshot facts for STM32MP1/STM32MP2)
4. Existing code: `targets/stm32/catalog` (the exact-part registry and
   `Stm32CuratedPartIds`), `targets/stm32/memory` (the T039 plan contracts),
   `targets/stm32/security`, `targets/stm32/workspace`, `targets/stm32/wireless`,
   `targets/stm32/extmem`, `analyzers/stm32` (the T043 signature gates and the
   T048 diff/CTF layer), `core/model/*` (topology, program strategy,
   firmware-source), the ESP providers (`targets/esp*`, `ghidra` loaders) as the
   established provider pattern, and `ghidra/stm32` applicator patterns.

Known baseline facts (do not re-derive by guesswork):

- The pinned T032 source catalog (`catalogs/stm32/2026-09-28/source-catalog.json`,
  repository-only, excluded from the extension ZIP) carries 2,240 reference
  records across 28 family labels including STM32MP1 and STM32MP2; those rows
  are source facts with pinned digests, not exact orderable-part identities, and
  the T032 review found wildcard/shortened device names in the audited
  Open-CMSIS-Pack MP-adjacent PDSCs. No exact STM32MP part is currently in the
  53-record curated allowlist, and the curated allowlist must not be broadened
  by T049 without new review evidence.
- The curated catalog, memory plans, applicability, security domains, board
  profiles, signature packs, vector behavior, workspaces, wireless records,
  external-memory plans, and the T048 diff/CTF layer are additive layers that
  already compose without mutating each other; T049 adds its own layer on the
  same terms.
- `docs/architecture.md` and `docs/support-matrix.md` describe every shipped
  layer and must gain a T049 description row; `THIRD_PARTY_NOTICES.md` changes
  only if new redistributable material is described.
- The established review lessons: typed diagnostics for out-of-range values,
  constructors that reject overlapping/duplicate/ambiguous records, exact-part
  binding for any Ghidra adapter, and `NO_ADAPTER_PURE_PLAN_ONLY` when no
  complete confirmed input exists.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: provider/topology/boot-chain/device-tree
  planning stays under `targets`/`formats`/`analyzers`; any Ghidra mutation
  stays under `ghidra` inside one rollback-capable transaction, idempotent,
  preserving user artifacts and never resurrecting deleted or renamed ones,
  bound to the program-recorded exact part (fail closed on disagreement).
- Do not modify T039-T048 artifacts or promote any support state (STM-019).
- Never invent a Cortex-A/Linux artifact, device-tree node, boot-chain step,
  trusted-firmware address, or shared-resource fact. STM-015: STM32MP devices
  are a separate heterogeneous/OS-aware workflow; they are never loaded as
  ordinary Cortex-M-only firmware.
- Reuse `ParserLimits`, `CancellationToken`, `AddressRange`, the T039 plan
  contracts, the T044 security-domain contracts, the T045 workspace
  cross-program contracts, the T043 signature evidence gates, and the
  exact-part digest-pinned catalog contracts.
- A provider cannot be `VERIFIED` until fixtures exercise every supported
  execution topology that applies (TOPO-006), including the Cortex-A/Cortex-M
  split and any selectable-boot case; unproven states stay `PLANNED` or
  `EXPERIMENTAL` with their evidence named.
- Research inputs must be pinned with digests and license review before any
  derived fact is generated; SLA0044/SLA0048-restricted archives stay local
  diagnostics only.

## 2. Implement

1. Research first: identify which exact STM32MP1/STM32MP2 parts have
   redistributable, pin-downable evidence (TF-A/U-Boot/OpenOCD/Linux devicetree
   sources, ST CMSIS headers) and record the license and digest audit before
   implementation. If no source clears the boundary, stop after the research
   slice and record the precise blocker (as T026A did) rather than inventing
   facts.
2. Implement the selected parts as distinct providers covering Cortex-A
   artifacts, Cortex-M firmware, boot chain, device tree, trusted/security
   domains, and shared resources as separate planned programs or explicit
   cross-program relationships per TOPO-004.
3. Optional Ghidra adapter: only if real-Ghidra tested (transaction,
   idempotence, preservation, non-resurrection, ambiguous no-op, exact-part
   binding). If none is added, record `NO_ADAPTER_PURE_PLAN_ONLY`.
4. Docs: update `docs/architecture.md` and `docs/support-matrix.md`, plus
   `THIRD_PARTY_NOTICES.md` only if new redistributable material is described.

## 3. Tests (test-first, meaningful)

- Pure unit tests: provider resolution, topology/boot-chain planning,
  device-tree and shared-resource classification over repository-authored or
  pinned fixtures, explicit unavailability, immutability, determinism, and
  shared-contract reuse.
- Boundary tests: truncated/oversized/duplicate/out-of-range/unknown/tamper
  paths, limits, and cancellation.
- Real-Ghidra integration tests only if an adapter is added.
- Keep the STM32/ESP Python suites green; record every optional-source skip
  exactly.

## 4. Acceptance gates (run and record actual output)

1. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew check verifyFormatting --no-daemon`
2. `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'`
3. `python3 -m unittest scripts/tests/test_generate_esp_catalog.py`
4. `python3 scripts/audit-stm32-memory-readiness.py --require-complete`
5. `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> scripts/verify-build-quality.sh` (must report two clean, uncached 22-action builds and a byte-identical ZIP)
6. `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`

Compilation alone is not verification. If a test fails, is skipped, or an
optional source is absent, record it exactly.

## 5. Evidence and continuity

- Add `.embedra/evidence/tasks/T049.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T049`,
  real exit status, result, artifacts).
- Update `.embedra/state.json` with a T049 section, check T049 complete, add it
  to `completedTasks`, set `nextTask` to T050 and the matching unchecked
  SpecKit task, update test counts, working tree, and artifacts with the new
  ZIP digest.
- Check the T049 box in `Embedra-SpecKit.md` and update the spec digest in
  state.
- Update `PROJECT_STATE.md` and write the next handoff prompt
  `.embedra/prompts/T050-*.md`.
- Do not modify T039-T048 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance or license
redistributability cannot be established for a researched input, implementing
T049 would require broadening the curated allowlist without new review
evidence, the shared analyzers or earlier layers would have to be duplicated or
weakened, or implementing T049 would require mutating T039-T048 data. The
prompt is also referenced by `state.evidence.nextTaskPrompt`, so the next
session picks it up automatically.
