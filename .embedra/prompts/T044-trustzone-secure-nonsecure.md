# T044 Handoff Command — STM32 TrustZone secure/non-secure regions and veneers

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T044** from
`Embedra-SpecKit.md`:

> T044 Implement TrustZone secure/non-secure region and veneer handling for
> supported devices.

Do **not** begin T045. Do not commit, push, or publish unless explicitly asked.

## 0. Baseline to verify first (stop and report on any mismatch)

- `git status --porcelain` is clean at commit `f356879` (T038–T043 plus the
  T038–T041 follow-up review fixes).
- `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh`
  pass.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state.
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0
  with `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11`.
- Curated catalog SHA-256 `afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9`,
  memory plans SHA-256 `00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66`,
  SVD applicability SHA-256 `be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518`.
- Latest reproducible artifact: `T038_T041_FOLLOWUP_REVIEW_REPRODUCIBLE_ARTIFACT`,
  4,186,433-byte ZIP SHA-256
  `02cb3efad54d903d6f0e7b03de0a8b5053591047499a8766c6ab3baff18edb9b`. If the
  shipped tree differs, re-run `scripts/verify-build-quality.sh` before relying
  on it.
- T044 is unchecked and next in `Embedra-SpecKit.md`; `state.nextTask` is T044.

Read in order:

1. `.embedra/state.json`
2. `.embedra/evidence/tasks/T043.md`, `T042.md`, `T041.md`, `T040.md`, `T039.md`
3. `.embedra/evidence/tasks/T039-T041-hardening.md`,
   `.embedra/evidence/tasks/T038-T041-followup-review.md`
4. `Embedra-SpecKit.md` (STM-004, STM-008, STM-009, STM-010, STM-011, STM-019,
   STM-020, and T044)
5. Existing region/topology code: `targets/stm32/memory/Stm32MemoryPlanner`,
   `targets/stm32/vector/*`, `targets/stm32/catalog/*`, `svd/Stm32Svd*`,
   `pack/Stm32SvdPackLoader`, `ghidra/stm32/Stm32SvdApplicator`, and their tests.

Known baseline facts (do not re-derive by guesswork):

- All 53 curated parts are `PLANNED` and every catalog `securityStatus` is
  `UNKNOWN`. The catalog `securityEvidence` lists are peripheral names
  (`AES`, `GTZC`, `PKA`, `SAES`, ...) only; they are not domain boundaries.
- 20 curated parts have Cortex-M33/M55 cores. Architectural TrustZone capability
  is **not** a pinned per-part security map; never infer a boundary from a core,
  family label, or sibling part.
- T039 memory plans currently mark `securityDomain` as `unpartitioned`
  (`CUSTOM`) and contain no secure/non-secure partition data. They must not be
  modified.
- Pinned sources available for evidence review:
  `catalogs/stm32/2026-09-28/cmsis-sources.json` and `cmsis-interrupts.json`
  (Apache-2.0 ST CMSIS device headers with per-file SHA-256),
  `T039-document-source-audit.json` (pinned ST RM/DS revisions; some entries are
  text digests because the byte-exact PDF was unavailable), and the T040 SVD
  packs (`SAU`, `GTZC`, `SYS_S`, ... peripheral windows). Board `.ioc` files
  named `...TrustZoneEnabled...` are repository-only board configuration
  evidence, not device region boundaries.
- Any new redistributable source material must be recorded with its exact
  upstream revision and per-file SHA-256; vendor PDFs stay local research inputs
  and are not packaged.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: security-domain planning, attribution, and
  veneer modeling stay under `targets`/`analyzers`; Ghidra mutation stays under
  `ghidra`. Do not import Ghidra APIs into pure packages.
- STM-010: represent TrustZone secure/non-secure images and veneers explicitly
  **only for applicable devices the pinned evidence supports**. Unavailable or
  ambiguous facts stay explicit and fail closed with a reason.
- STM-019: every exact part keeps its explicit `PLANNED`/`EXPERIMENTAL`/
  `VERIFIED`/`UNSUPPORTED` state. No support state is promoted by T044.
- Do not modify the curated catalog, T039 memory plans, T040 device-data packs,
  T041 vector behavior, T042 board profiles, or T043 signature packs.
- Never invent a security domain boundary, SAU/IDAU attribute, veneer/NSC
  address, or boot address. No family or wildcard inference.
- Reuse `ParserLimits`, `CancellationToken`, and the pack
  manifest/integrity/provenance contracts.
- Apply the review lessons: encoding-safe XML rejection before parsing (see
  `ensure_safe_xml` in the T040/T039 generators), typed diagnostics for
  out-of-range values, and model constructors that reject overlapping/duplicate
  records.

## 2. Implement

1. **Pure security-domain model** (`targets/stm32/security` or an equivalently
   named package): immutable per-exact-part domain/region records with explicit
   attributes (`SECURE`, `NON_SECURE`, `NON_SECURE_CALLABLE`), address ranges,
   provenance, and an explicit `UNAVAILABLE` state plus reason. A record with no
   pinned evidence must not exist as a fabricated boundary.
2. **Digest-pinned snapshot + loader**: add `catalogs/stm32/2026-09-29/security-domains.json`
   and `.sha256`, generated deterministically by
   `scripts/generate-stm32-security-domains.py` from pinned sources. The loader
   must verify the artifact digest, schema, linked curated-selection digest, and
   exact-part membership, and fail closed on tamper/malformed input.
3. **Veneer handling (pure)**: model secure/non-secure callable transitions and
   boundaries with evidence IDs. Do not fabricate veneer addresses or instruction
   semantics; an evidence-backed veneer match never establishes device support.
4. **Composition and validation**: compose with a validated T039
   `Stm32MemoryPlanner.Plan` without mutation; reject overlap with memory
   regions, missing evidence, unsupported cores, duplicate/ambiguous domains, or
   an unavailable part.
5. **Optional Ghidra adapter**: only if it is in scope and real-Ghidra tested.
   If added, bind to the program-recorded exact part (fail closed on
   disagreement, as in `Stm32SvdApplicator`/`Stm32VectorLabelApplicator`), apply
   inside one rollback-capable transaction, be idempotent, preserve user
   artifacts, and never resurrect deleted/renamed artifacts. If no adapter is
   added, record `NO_ADAPTER_PURE_PLAN_ONLY` explicitly in evidence, as T042 did.
6. **Docs**: update `docs/architecture.md` and `docs/support-matrix.md`, plus
   `THIRD_PARTY_NOTICES.md` if new redistributable material is described.

## 3. Tests (test-first, meaningful)

- Pure unit tests: attribute/region invariants, exact-part applicability and
  explicit unavailability, composition immutability vs. the T039 plan,
  overlap/ambiguity fail-closed, unknown configuration input, malformed records.
- Generator tests: deterministic regeneration matching the committed digest,
  tamper rejection, and pinned-source hash checks.
- Boundary tests: truncated, oversized, duplicate, out-of-range, wrong-attribute,
  and unknown-domain records.
- Real-Ghidra integration tests only if an adapter is added (transactional
  apply, rollback, idempotence, preservation, non-resurrection, ambiguity
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

- Add `.embedra/evidence/tasks/T044.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T044`,
  real exit status, result, artifacts).
- Update `.embedra/state.json`: add a `stm32TrustZone` (or equivalent) section,
  check T044 complete, add it to `completedTasks`, set `nextTask` to T045 and the
  matching unchecked SpecKit task, update test counts, working tree, and
  artifacts with the new ZIP digest.
- Check the T044 box in `Embedra-SpecKit.md` and update the spec digest in state.
- Update `PROJECT_STATE.md` and write the next handoff prompt
  `.embedra/prompts/T045-*.md`.
- Do not modify T039–T043 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for a security-domain source, the only available links are family or
wildcard inference, or implementing T044 would require mutating T039–T043 data.
