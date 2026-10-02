# Independent Review Command — T039–T047 (STM32 device support)

Work in `/home/rez0x61/Projects/ghidra_extension`. Your job is an **independent
adversarial review and verification of every change, artifact, and evidence
claim produced by tasks T039 through T047** in `Embedra-SpecKit.md`. You review
and verify only; you do not fix anything, you do not begin any SpecKit task,
and you do not commit, push, or publish.

> T039 catalog-driven STM32 memory-region and execution-topology planning
> T040  CMSIS-SVD/device-data transformation with provenance
> T041  Vector labels/functions and Cortex-M core exception structures
> T042  Board profiles for external flash/RAM and boot offsets
> T043  STM32 HAL/LL/CMSIS/FreeRTOS signature-pack generation and matching
> T044  TrustZone secure/non-secure region and veneer handling
> T045  Dual-core/heterogeneous workspace planning
> T046  WB/WB0/WL/WBA wireless/network-core distinctions
> T047  External-memory loaders and OCTOSPI/FMC mapping

This is a read-only audit. The only files you may create are scratch files
under `/tmp/opencode`; write nothing into the repository.

## 0. Hard constraints

- Read-only: never modify, create (except `/tmp/opencode` scratch), delete,
  revert, format, or commit any repository file. Never run `git add/commit/
  checkout/restore/clean`. Never push or publish.
- Do not run networked scripts (`check-stm32-market-drift.py`,
  `discover-stm32-dfp-sources.py`, anything that downloads sources). Do not
  download any vendor source. Offline verification only.
- Use exactly the pinned toolchain for every Gradle run:
  `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64` and
  `GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`
  (JDK 21.0.12, Ghidra 12.1.3 PUBLIC). Do not use another JDK or Ghidra.
- If you run `scripts/verify-build-quality.sh` (see §5), it regenerates
  `dist/ghidra_12.1.3_PUBLIC_20261002_Embedra.zip`; immediately afterwards
  confirm its SHA-256 is still the pinned digest in §1 — a different digest on
  the same tree is a MAJOR finding (reproducibility regression).
- Report findings; never silently fix or paper over them. Compilation alone is
  never verification.

## 1. Baseline to verify first (stop and report on mismatch)

Record each check's actual output before reviewing anything:

1. `git log --oneline -5` — HEAD must be `07f9b61`; the T039–T043
   implementation is committed in `f356879` ("Implement STM32 T039-T043 device
   support and T038-T041 review fixes"); the T044–T047 (and T048) work is
   intentionally uncommitted on top. `git status --porcelain` must NOT be
   clean; that is by design. Do not commit.
2. `sha256sum Embedra-SpecKit.md` must equal `.specification.sha256` in
   `.embedra/state.json` (currently
   `e16dcfa8d1d9216ba3d6d4669463b4346af0ddfc75fd690d15be9323662d979c`, because
   the tree already carries the checked T048 box).
3. `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
   — both must exit 0.
4. `python3 scripts/audit-stm32-memory-readiness.py --require-complete` —
   exit 0 with `readyCount 53`, `incompleteParts {}`, `unresolvedFlash 11`,
   `catalogSha256 afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`,
   `memoryPlansSha256 00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`.
5. Pinned snapshots must match today (any mismatch is a BLOCKER):
   - `catalogs/stm32/2026-09-29/curated-catalog.json`
     `afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`
   - `catalogs/stm32/2026-09-29/memory-plans.json`
     `00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`
   - `catalogs/stm32/2026-09-29/svd-applicability.json`
     `be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518`
   - `catalogs/stm32/2026-09-29/security-domains.json`
     `08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9`
   - `catalogs/stm32/2026-09-29/board-profiles.json`
     `78a3e0e41cc14585ad3c4140aed80fff6d53fcd367d6beec3d2cc787950c75f3`
   - `catalogs/stm32/2026-09-29/selection.json`
     `1d4b971f0264815492bf644552b8c83abf0393b627216a89640080b8ccf8b3b4`
   - `packs/stm32.stm32f1.signatures/1.0.0/signatures.json`
     `c21f553e30a5d02b30aaafa4bd0584ac3deaf304b23d895d7d692cedbbd8dc70` and
     `packs/stm32.stm32f1.signatures/1.0.0/pack.json`
     `7f80d9f9bfb553da5545ceb5467f45e506b525a02851828043a034361b840100`
     (aggregate content digest pinned in the manifest:
     `ebb0e4e72b435d13b23f42945fc5e62056d82b390921e5ad5a007bc2b227a191`)
   - all `packs/stm32.*.svd/1.0.0/{pack.json,registers.json}` load and verify
     through `Stm32BundledPacks`/`Stm32SvdPackLoader` (digest re-check).
6. Current-tree test/verification baseline (the T048 final gate, since the tree
   also carries the T048 layer): 378 unit tests, 104 real-Ghidra tests, 131
   STM32 Python tests (`OK (skipped=4)`), 4 ESP Python tests, and a
   reproducible 4,432,899-byte extension ZIP with SHA-256
   `f530fbf952f89ca025b268a7f0d10c5c9138a718364b75b1d663006c4a82852d`.
   Per-task historical ZIP digests recorded inside `.embedra/evidence/tasks/
   T039.md`…`T047.md` are recorded history — the tree has moved on since — so
   do NOT fail the review because an intermediate digest no longer reproduces;
   the current-tree gate in §5 is the authoritative verification.

## 2. Scope boundary — what is in and out of review

In scope: everything T039–T047 shipped or changed, i.e.

- `src/main/java/io/github/rezabakhshi/embedra/targets/stm32/memory/`
  (`Stm32MemoryPlanner` + `package-info.java`)
- `src/main/java/io/github/rezabakhshi/embedra/svd/Stm32Svd*.java`
- `src/main/java/io/github/rezabakhshi/embedra/targets/stm32/catalog/`
  (`Stm32SvdApplicability`, `Stm32InterruptPlan`)
- `src/main/java/io/github/rezabakhshi/embedra/targets/stm32/vector/`
- `src/main/java/io/github/rezabakhshi/embedra/targets/stm32/board/`
- `src/main/java/io/github/rezabakhshi/embedra/analyzers/stm32/`
  (`Stm32LibrarySignature`, `Stm32SignaturePack`, `Stm32SignaturePackLoader`,
  `Stm32SignaturePackSelection`, `Stm32SignatureContext`, `Stm32FunctionBytes`,
  `Stm32SignatureMatcher`, `Stm32SignatureMatch`, `Stm32SignatureNonMatch`,
  `Stm32SignatureMatchReport`)
- `src/main/java/io/github/rezabakhshi/embedra/targets/stm32/security/`
- `src/main/java/io/github/rezabakhshi/embedra/targets/stm32/workspace/`
- `src/main/java/io/github/rezabakhshi/embedra/targets/stm32/wireless/`
- `src/main/java/io/github/rezabakhshi/embedra/targets/stm32/extmem/`
- `src/main/java/io/github/rezabakhshi/embedra/ghidra/stm32/`
  (`Stm32SvdApplicator`, `Stm32DeviceDataReport`, `Stm32VectorApplicator`,
  `Stm32VectorApplicationReport`, `Stm32VectorLabelApplicator`,
  `Stm32ExternalMemoryApplicator`, `Stm32ExternalMemoryReport`,
  `Stm32MappingException`, `Stm32BundledPacks`)
- `src/test/java/io/github/rezabakhshi/embedra/...` for all of the above
- `src/integrationTest/java/io/github/rezabakhshi/embedra/ghidra/stm32/`
  (`Stm32SvdApplicatorTest`, `Stm32VectorApplicatorTest`,
  `Stm32VectorLabelApplicatorTest`, `Stm32ExternalMemoryApplicatorTest`,
  `Stm32RawBinImporterTest`, `Stm32AddressedInputInspectorTest`)
- `packs/stm32.*.svd/1.0.0/`, `packs/stm32.stm32f1.signatures/1.0.0/`
- `catalogs/stm32/2026-09-29/{memory-plans.json,svd-applicability.json,
  board-profiles.json,security-domains.json}` (+ `.sha256` companions)
- `scripts/generate-stm32-{svd-applicability,svd-packs,board-profiles,
  signatures,security-domains}.py`, `scripts/generate-stm32-memory-*.py`,
  `scripts/audit-stm32-memory-readiness.py`,
  `scripts/cache-stm32-memory-documents.py`,
  `scripts/validate-stm32-fixture-catalog.py`
- `.embedra/evidence/tasks/T039…T047.md` and the two review-fix evidence
  files `T039-T041-hardening.md`, `T038-T041-followup-review.md` (+ their
  sidecar `.json` audits), `docs/architecture.md`,
  `docs/support-matrix.md`, `THIRD_PARTY_NOTICES.md`,
  `scripts/verify-build-quality.sh` (ZIP-entry oracle section)

Out of scope (do not review, but they exist uncommitted in the tree): the T048
diff/CTF layer — `analyzers/stm32/{Stm32FirmwareRole,Stm32FirmwareArtifact,
Stm32ArtifactDiff,Stm32FirmwareDiffContext,Stm32FirmwareDiffAnalyzer,
Stm32FirmwareDiffReport,Stm32CtfLead,Stm32SecurityEvidence,
Stm32CtfEnrichmentContext,Stm32CtfEnrichmentAnalyzer,
Stm32CtfEnrichmentReport}.java`, the two T048 test classes
(`Stm32FirmwareDiffAnalyzerTest`, `Stm32CtfEnrichmentAnalyzerTest`), the T048
paragraphs in the two docs, `.embedra/evidence/tasks/T048.md`, the T048
command records, and `.embedra/prompts/T049-*.md`. Flag it as a MAJOR finding
if T039–T047 code behaves differently because of a T048 file (there must be
zero coupling; T048 only reads T039–T047 contracts).

Useful diff commands for the uncommitted work (do not stage anything):
- `git diff --stat f356879 -- src/main/java src/test/java src/integrationTest/java scripts docs`
- `git diff f356879 -- <path>` for any uncommitted file
- `git show --stat f356879` for the committed T039–T043 shape

## 3. Read in order (before judging any code)

1. `.embedra/state.json` (sections `stm32MemoryReview`,
   `stm32SvdEnrichment`, `stm32VectorLabels`, `stm32BoardProfiles`,
   `stm32SignaturePacks`, `stm32TrustZone`, `hardeningReview`,
   `followupReview`, `stm32DualCoreWorkspace`,
   `stm32WirelessNetworkCores`, `stm32ExternalMemory`) and
   `.embedra/evidence/tasks/T047.md`
2. `.embedra/evidence/tasks/T046.md`, `T045.md`, `T044.md`, `T043.md`,
   `T042.md`, `T041.md`, `T040.md`, `T039.md`, plus
   `T039-T041-hardening.md` and `T038-T041-followup-review.md`
3. `Embedra-SpecKit.md`: the T039–T047 task lines; STM-004..STM-021 (esp.
   STM-009, STM-012, STM-016, STM-017, STM-019, STM-020, STM-021);
   TOPO-001..TOPO-006; AN-003/AN-014 false-positive rules; ADR 0026
4. The SpecKit review conventions these tasks must honor: exact-part-only
   identity (no family/wildcard inference), explicit unavailability with
   reasons, digest-pinned additive snapshots, fail-closed typed diagnostics,
   and `NO_ADAPTER_PURE_PLAN_ONLY` where no complete confirmed input exists.

## 4. Review checklist

### 4.1 Cross-cutting invariants (verify in code, not from docs)

For every file in §2 scope, verify:

- **Pure/adapter boundary**: no `ghidra.` import or qualified reference under
  `core`, `formats`, `targets`, `analyzers`, `pack`, `svd`; all Ghidra
  mutation confined to `ghidra/stm32` (spot-check
  `ArchitectureBoundaryTest` still covers the new packages).
- **Immutability**: records defensively copy arrays/lists/maps
  (`List.copyOf`, `bytes.clone()` on input and in accessors); no mutable
  field escapes; collection results reject mutation.
- **Determinism**: sorted outputs; no iteration over `HashMap`/`HashSet`
  where order reaches a report; no timestamps, host paths, locales, or
  random seeds in any produced model.
- **Fail-closed typed diagnostics**: stable enum diagnostic codes (e.g.
  `EXTERNAL_*`, `LOADER_*`, `SECURITY_*`, `WORKSPACE_*`, `WIRELESS_*`) for
  binding/mismatch/ambiguity; typed diagnostics (not string-matching) for
  out-of-range values; constructors reject overlapping, duplicate, and
  ambiguous records; no silent defaulting.
- **No invented facts**: every address, size, name, permission, alias, or
  support claim traces to a pinned digest-checked snapshot or an explicit
  `USER_ASSERTION`; absent evidence is an explicit non-match/unavailable
  entry, never a fabricated value; no family/sibling/wildcard inference.
- **STM-019**: `supportState()` everywhere returns `PLANNED`; no code path
  promotes `PLANNED` → `EXPERIMENTAL`/`VERIFIED` for any of the 53 parts.
- **Shared-contract reuse**: `ParserLimits`, `CancellationToken`,
  `AddressRange`/`SourceRange` used instead of ad-hoc bounds; the T043
  evidence gates (family/compiler/optimization) are enforced before any
  signature is applied; pack loading goes through the shared
  `LocalPackRepository` selection path.
- **Redaction/secrets**: no firmware bytes, key material, or restricted
  capture names in any report model; explanations carry provenance, not
  payloads; ZIP text-content scan (`verify-build-quality.sh`) still guards
  host paths and restricted names.

### 4.2 Per-task focus (claims vs. code)

- **T039** (`targets/stm32/memory`, `memory-plans.json`,
  `audit-stm32-memory-readiness.py`): validated plan construction fails on
  incomplete mandatory properties; region/alias/bit-band arithmetic
  (`Math.multiplyExact`, half-open ranges, 32-bit fits); H735
  `ITCM_AXI_SHARED` allocations resolved concretely; WB15/WB55
  `sharedAccess` metadata; the 11 null catalog `flashKiB` fields documented
  as a known limitation, not silently paired; the audit script digests the
  catalog and fails `--require-complete`.
- **T040** (`svd/Stm32Svd*`, `Stm32SvdApplicability`, `Stm32InterruptPlan`,
  `Stm32SvdApplicator`, `generate-stm32-svd-packs.py`, shipped packs):
  applicability is exact device-line or named review override only; closed
  schemas; encoding-safe DTD/entity rejection (not byte-substring) in
  `generate-stm32-svd-packs.py` with the UTF-16 regression; typed
  `PACK_CONTENT_INVALID` for out-of-range interrupt values; overlapping
  fields and duplicate field/enumerated-value names rejected; derivedFrom,
  `dim` arrays, clusters, alternate views expanded deterministically;
  applicator: one rollback-capable transaction, volatile/read-write
  peripheral blocks, existing blocks/symbols/instructions preserved
  (`IMPORTED` provenance), idempotent reapply, program-recorded exact-part
  binding (`PACK_INCOMPATIBLE` on disagreement), interrupt definitions as
  data types/provenance only (no vector labels — those are T041); shipped
  packs' contents (7,512 registers / 47,440 fields / 22,725 enumerated
  values across 8 parts) re-derivable from the committed pack JSON.
- **T041** (`targets/stm32/vector`, `Stm32VectorLabelApplicator`): the
  explicit nine-entry core-exception table; architectural reset slot;
  canonicalized exception names; unlisted pinned exceptions preserved with
  `UNLISTED_CORE_EXCEPTION`; conditional/variant interrupt lists produce
  non-applicable plans; handler addresses only from confirmed words inside
  the caller-supplied image range; the applicator creates primitive words +
  qualified labels + handler functions in one transaction, preserves user
  symbols/functions/data/instructions/comments, records deterministic
  conflicts, never resurrects deleted/renamed artifacts (receipt addresses
  retained), and binds to the program-recorded exact part.
- **T042** (`targets/stm32/board`, `board-profiles.json`,
  `generate-stm32-board-profiles.py`): digest-checked catalog (snapshot +
  selection + board-index digests); exact-part-only profile resolution; no
  MCU-pack mutation; external regions in the `ext-mem` address space with
  quoted BSP/CMSIS evidence; numeric collision checks against MCU plan
  regions (space-tag-ignoring, per T042's documented rule); boot offsets
  must land inside an external region; 9 reviewed + 3 explicitly
  unavailable profiles; unavailability reasons match the pinned snapshot.
- **T043** (`analyzers/stm32` signatures, `generate-stm32-signatures.py`,
  the F1 pack): relocation masking (every ELF-relocation-touched byte
  masked `00`), mask alphabet `{00,ff}`, ≥8-byte patterns with ≥1
  significant byte, deterministic regeneration (the committed pack equals
  the generator's output modulo the pinned STM32Cube input), loader
  verifies identity/provenance/license/`ALLOWED` redistribution/aggregate
  digest/closed schema, matcher: `EVIDENCE_MISSING` scans nothing,
  `INDEX_UNAVAILABLE`, `NO_MATCH` bounded at 128 details + 1 overflow
  summary, VERIFIED only for fully-specified masks, and pack selection via
  `LocalPackRepository` (`Stm32SignaturePackSelection`).
- **T044** (`targets/stm32/security`, `security-domains.json`,
  `generate-stm32-security-domains.py`): digest-pinned snapshot verifying
  curated-catalog/selection/header-evidence/interrupt-index/memory-plan
  digests; windows exist only where the pinned header symbol, T039 alias,
  and reviewed alias agree; 19 pinned / 34 explicitly unavailable with the
  two pinned reasons; partitions/NSC stay `UNRESOLVED_CONFIGURATION_
  DEPENDENT`/`UNAVAILABLE`; no veneer address or instruction semantic
  fabricated; `Stm32SecurityPlanner` composition fail-closed set
  (`SECURITY_*`); `Stm32VeneerPlanner` matches only pinned NSC + declared
  transition + evidence id; no Ghidra adapter.
- **T045** (`targets/stm32/workspace`): program slots only for
  independently supplied executable domains; exactly WB55/WB15
  `MULTI_CORE_PINNED`, 51 explicit `UNAVAILABLE` (incl. all four H7
  parts); per-region attribution only from pinned `sharedAccess`; pinned
  IPCC `0x58000C00`/HSEM `0x58001400` windows and `RELEASES_FROM_RESET`
  boot order re-emitted as typed cross-program references; CPU2 image
  domain `UNAVAILABLE_INDEPENDENTLY_SUPPLIED`, CPU2 fetch view an explicit
  unresolved view; the full `WORKSPACE_*` fail-closed diagnostic set;
  inputs held by identity (non-mutating composition).
- **T046** (`targets/stm32/wireless`): classification from pinned topology
  only (2 `NETWORK_CORE_PINNED`, 8 `SINGLE_APPLICATION_CORE`, 43
  `WIRELESS_FAMILY_OUT_OF_SCOPE`); coprocessor firmware independently
  supplied with C2BOOT/C2OPT/SBRV unresolved; radio register models
  unavailable/deferred per pinned applicability; `evaluateNetworkCoreImage`
  classifies only against pinned CPU2 attribution (bindable-unresolved,
  flash-view-configuration-dependent, partial/unattributed fail closed);
  the shipped WB55 CM4/CM0P packs verified to contain no RF/RADIO/BLE
  peripheral (re-verify from the committed pack JSON).
- **T047** (`targets/stm32/extmem`, `Stm32ExternalMemoryApplicator`):
  window/aperture separation with checked translation; numeric collisions
  (windows ↔ MCU regions, window ↔ window) fail closed regardless of the
  `ext-mem` tag; controller family projection is mechanical
  (OCTOSPI/XSPI/QUADSPI/FMC, unrecognized fails closed); custom profiles
  require a `USER_ASSERTION`, an exact curated part, closed schemas, and
  fail closed on malformed/truncated/oversized/duplicate/overlapping
  input; `planLoad` bounds (positive length, device-extent containment,
  `maxInputBytes`/`maxExtractedBytes`, single-block); the applicator:
  `MAP_WINDOWS`/`LOAD_BYTES` in one `GhidraProgramTransaction`, exact-part
  binding across all recorded provenance namespaces, idempotence,
  `MEMORY_PRESERVED`/`NAME_CONFLICT`/`CONTENT_DIFFERS`/`PRESERVED_ABSENT`
  receipts, never removes/splits/overwrites/resurrects a block, and
  window-mapping vs byte-loading remain alternative workflows (no merge
  into a mapped aperture).

### 4.3 Tests and verification quality

- The pure tests actually assert behavior (not just "does not throw");
  check boundary coverage per task: truncated/oversized/duplicate/
  out-of-range/unknown/tamper paths, limits (`LIMIT_EXCEEDED`),
  cancellation (`CANCELLED`), immutability, determinism.
- Real-Ghidra tests assert transaction rollback, idempotence, preservation,
  non-resurrection, ambiguous no-op, and exact-part binding for every
  adapter (T040/T041/T047); T042/T044/T045/T046 must have NO adapter and
  their evidence must say `NO_ADAPTER_PURE_PLAN_ONLY`.
- No test is silently skipped; the STM32 Python suite's 4 skips are exactly
  the documented optional-source checks: two ephemeral pinned-source
  download checks (`test_local_sources_match_pinned_hashes`,
  `test_ephemeral_sources_regenerate_identical_evidence_and_reject_changes`
  in the memory-candidates/header-evidence tests) and two STM32Cube F1
  regeneration checks (`test_regeneration_matches_committed_pack`,
  `test_regeneration_rejects_a_tampered_copy`) requiring
  `EMBEDRA_STM32CUBE_ROOT`. Verify skip reasons with
  `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py' -v`.
- Evidence files' verification tables match the reality of the code they
  describe (class names, diagnostic codes, counts, file lists). Recount
  what is cheap to recount: T044's 19/34, T045's 2/51, T046's 2/8/43,
  T047's 9/3/41, T043's 1,543 signatures (1,111 HAL / 225 kernel / 179 LL /
  24 port / 4 CMSIS).

### 4.4 Docs and continuity consistency

- `docs/architecture.md` and `docs/support-matrix.md` contain a T039–T047
  description for every shipped layer, and those descriptions do not claim
  more than the code does (especially: no hardware verification, no
  fixture-corpus claims, `PLANNED` everywhere).
- `THIRD_PARTY_NOTICES.md` matches what is actually redistributed: T043's
  notice section (BSD-3-Clause HAL/LL, Apache-2.0 CMSIS Device, MIT
  FreeRTOS; no source/object/runtime bundled) is present and accurate.
- `.embedra/state.json`: every T039–T047 section is internally consistent
  with its evidence file and the code; `hardeningReview.residualBacklog`
  and `followupReview.residualNotes` items are accurately described and
  still present in the code (or note if one has silently disappeared);
  `completedTasks`, `currentTask`, `nextTask`, SpecKit checkboxes, and
  `.embedra/evidence/commands.jsonl` agree.
- `scripts/verify-build-quality.sh`: the 22-action list, the exact ZIP-entry
  oracle, and the host-path/restricted-name scans still match the shipped
  tree.

## 5. Verification to actually run (record real outputs)

Run in this order; every command must pass and its output goes into the
report:

1. `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew check verifyFormatting --no-daemon`
   (expect 378 unit + 104 real-Ghidra, Checkstyle/JaCoCo/formatting/
   catalog/fixture/scaffold pass)
2. `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'`
   (expect `Ran 131 tests ... OK (skipped=4)`)
3. `python3 -m unittest scripts/tests/test_generate_esp_catalog.py`
   (expect 4 tests OK — regression guard that T039–T047 touched nothing ESP)
4. `python3 scripts/audit-stm32-memory-readiness.py --require-complete`
   (expect exit 0, 53/53, unresolvedFlash 11)
5. `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC scripts/verify-build-quality.sh`
   (expect two clean, uncached 22-action builds and a byte-identical
   4,432,899-byte ZIP; afterwards re-run the §1 digest check on the ZIP)
6. `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`

Targeted spot-checks (optional but recommended, no network):
- Re-derive two or three T039 plans straight from `memory-plans.json`
  regions/aliases and compare against `audit` output.
- Re-verify T043 masking: pick a masked signature from the committed pack
  and confirm its mask alphabet and that the claimed source file digest is
  recorded in `T043-signature-source-audit.json`.
- Re-run the T044 pinned/unavailable partition and the T046
  shipped-pack radio-absence check from the committed JSONs.
- Confirm `Stm32ExternalMemoryApplicator` has no code path that deletes,
  splits, or overwrites an existing block (read the full class).

## 6. Report format (your final response)

Produce a single markdown report with exactly these sections:

1. **Verdict** — one of `APPROVED`, `APPROVED_WITH_NOTES`,
   `CHANGES_REQUESTED`, `BLOCKED`, with a two-sentence justification.
2. **Baseline verification** — table of §1 checks with actual outputs.
3. **Gate results** — table of §5 commands with actual exit statuses and
   counts (quote the real numbers; do not paraphrase into "passing").
4. **Per-task verdicts** — one row per task T039…T047: `PASS`, `PASS_WITH_
   NOTES`, or `FAIL`, plus the specific claim(s) you verified in code.
5. **Findings** — every finding as: ID (R-01, R-02, …), severity
   (`BLOCKER`, `MAJOR`, `MINOR`, `NOTE`), task(s) affected, `file:line`,
   description, and suggested remediation (describe it; do not implement).
   A BLOCKER is a broken invariant (support-state promotion, invented fact,
   boundary violation, digest mismatch, data loss in an adapter, a failing
   or silently-skipped gate). A MAJOR is a misleading claim, missing
   fail-closed path, or reproducibility regression. MINOR is style,
   docs-wording, or test-coverage depth. NOTE is an observation.
6. **Residual backlog accuracy** — whether the documented residuals
   (§4.4) still exist and are correctly described; list any undocumented
   residual you discovered as a finding.
7. **Limitations of this review** — what you could not verify (e.g., no
   hardware, generator regeneration sources absent, historical per-task
   ZIP digests not reproducible) stated plainly.

If a mandatory gate fails, or any pinned digest mismatches, stop the review
at that point, report `BLOCKED` with the actual output, and do not speculate
beyond it.
