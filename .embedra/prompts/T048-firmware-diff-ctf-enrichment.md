# T048 Handoff Command — STM32 firmware diff and CTF enrichment using the shared analyzers

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T048** from
`Embedra-SpecKit.md`:

> T048 Implement STM32 firmware diff and CTF enrichment using the shared
> analyzers.

Do **not** begin T049. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- The T047 working tree is uncommitted (baseline commit `f356879` plus the
  T038-T047 work); `git status --porcelain` is not clean by design. Do not
  commit.
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
  pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state
  (`c6279da2138c1bbdbb65797db69eadc4812ff7312ca7b3ece6b87e81e514cec1`).
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
- Local toolchain for every gate below: `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64`
  and `GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`
  (JDK 21.0.12, Ghidra 12.1.3 PUBLIC).
- T039-T047 checkboxes are checked; `state.nextTask` is T048 and the T048 line
  is unchecked.
- Current repository verification baseline (T047 final gate): 353 unit, 104
  real-Ghidra, 131 STM32 Python (4 documented optional-source skips), and 4 ESP
  Python tests; two clean, uncached 22-action builds; byte-identical
  4,391,353-byte ZIP SHA-256
  `0f50ba57c2cd68c112f93f1259de5490f1d0722e9428f74c31cd56ca2aee3bcf`
  (`T047_REPRODUCIBLE_ARTIFACT`). If the shipped tree differs, re-run
  `scripts/verify-build-quality.sh` before relying on it.

Read in order:

1. `.embedra/state.json` and `.embedra/evidence/tasks/T047.md`
2. `.embedra/evidence/tasks/T046.md`, `T045.md`, `T044.md`, `T043.md`,
   `T042.md`, `T041.md`, `T040.md`, `T039.md`
3. `Embedra-SpecKit.md` (T048; STM-009, STM-012, STM-016, STM-017, STM-019,
   STM-020; TOPO-001..006; and the shared-analyzer requirements T023, T024,
   T025 with their ADRs)
4. Existing code: `analyzers` (the T023 metadata/logging/FreeRTOS/signature
   enrichment, the T024 security evidence, and the T025 artifact-diff and
   ESP-oriented CTF findings layers, including their shared
   limits/cancellation/redaction contracts), `targets/stm32/extmem` (the T047
   external-memory plan/load contracts), `targets/stm32/wireless`,
   `targets/stm32/workspace`, `targets/stm32/memory`,
   `targets/stm32/catalog`, `ghidra/stm32` applicator patterns, and
   `core/model/*`.

Known baseline facts (do not re-derive by guesswork):

- The "shared analyzers" of T048 are the implemented pure ESP enrichment/
  diff/CTF layers from T023 (`EspIdfEnrichment` facts, logging-call resolution,
  FreeRTOS symbols, library-signature analysis), T024 (security evidence),
  and T025 (artifact diff, ranked leads, redaction), plus the T043 STM32
  signature matcher. T048 consumes them for STM32 inputs; it does not
  reimplement or weaken them, and any gap the shared contract leaves must
  become an explicit diagnostic rather than an invented fact.
- T047 shipped `targets/stm32/extmem`: `Stm32ExternalMemoryPlan` (pinned T042
  windows or confirmed custom profiles, 9/3/41 pinned-mapped, pinned-
  unavailable, no-profile partition), `MappingWindow` with checked
  aperture/device-offset translation, `planLoad` bounded load placement, and
  the `Stm32ExternalMemoryApplicator` adapter (MAP_WINDOWS/LOAD_BYTES,
  exact-part bound, idempotent, preservation and `PRESERVED_ABSENT` receipts).
  T047's evidence records that window mapping and byte loading are alternative
  workflows for one program because existing memory is never split.
- The curated catalog, memory plans, applicability, security domains, board
  profiles, signature packs, vector behavior, workspaces, wireless records,
  and external-memory plans are additive layers that already compose without
  mutating each other; T048 adds its own layer on the same terms.
- `docs/architecture.md` and `docs/support-matrix.md` describe every shipped
  layer and must gain a T048 description row; `THIRD_PARTY_NOTICES.md` changes
  only if new redistributable material is described.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: diff and CTF planning/enrichment stay under
  `targets`/`analyzers`; any Ghidra mutation stays under `ghidra` inside one
  rollback-capable transaction, idempotent, preserving user artifacts and
  never resurrecting deleted or renamed ones, bound to the program-recorded
  exact part (fail closed on disagreement).
- Do not modify T039-T047 artifacts or promote any support state (STM-019).
- Never invent a diff result, CTF lead, confidence, symbol, or memory fact.
  Every finding originates from the shared analyzer contracts plus confirmed
  inputs, failing closed otherwise; a shared analyzer's absent evidence stays
  an explicit non-match rather than an invented finding.
- Reuse `ParserLimits`, `CancellationToken`, `AddressRange`, the T039 plan
  contracts, the T042 board-profile contracts, the T043 signature evidence
  gates, and the exact-part digest-pinned catalog contracts.
- Apply the review lessons: typed diagnostics for out-of-range values,
  constructors that reject overlapping/duplicate/ambiguous records, and
  exact-part binding for any Ghidra adapter.
- A diff or CTF finding is a lead with provenance and bounded confidence; it
  never proves exploitability or device support, and secrets/credentials are
  redacted by the shared rules, not re-invented.

## 2. Implement

1. STM32 firmware diff: validate and compare firmware artifacts using the
   shared T025 diff contract (unchanged/moved/modified/added/removed views)
   over confirmed STM32 inputs, with per-part binding and stable diagnostics.
2. STM32 CTF enrichment: apply the shared analyzers (logging/assert recovery
   where its evidence contract permits, signature matches through the T043
   evidence gates, security evidence where pinned, and the shared
   redaction/false-positive rules) to STM32 firmware and produce ranked,
   provenance-bearing leads; unavailable evidence stays explicitly
   unavailable.
3. Optional Ghidra adapter: only if real-Ghidra tested (transaction,
   idempotence, preservation, non-resurrection, ambiguous no-op, exact-part
   binding). If none is added, record `NO_ADAPTER_PURE_PLAN_ONLY`.
4. Docs: update `docs/architecture.md` and `docs/support-matrix.md`, plus
   `THIRD_PARTY_NOTICES.md` only if new redistributable material is described.

## 3. Tests (test-first, meaningful)

- Pure unit tests: diff and enrichment composition over repository-authored
  STM32 fixtures, per-part binding, explicit unavailability, immutability,
  determinism, and shared-analyzer reuse.
- Boundary tests: truncated/oversized/duplicate/out-of-range/unknown/tamper
  paths, redaction and false-positive behavior, limits, and cancellation.
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

- Add `.embedra/evidence/tasks/T048.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T048`,
  real exit status, result, artifacts).
- Update `.embedra/state.json` with a T048 section, check T048 complete, add it
  to `completedTasks`, set `nextTask` to T049 and the matching unchecked
  SpecKit task, update test counts, working tree, and artifacts with the new
  ZIP digest.
- Check the T048 box in `Embedra-SpecKit.md` and update the spec digest in
  state.
- Update `PROJECT_STATE.md` and write the next handoff prompt
  `.embedra/prompts/T049-*.md`.
- Do not modify T039-T047 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for a diff or finding input, the shared analyzers would have to be
duplicated or weakened, or implementing T048 would require mutating T039-T047
data. The prompt is also referenced by state.evidence.nextTaskPrompt, so the
next session picks it up automatically.
