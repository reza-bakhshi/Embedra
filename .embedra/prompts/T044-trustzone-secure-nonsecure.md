# T044 Handoff Command — STM32 TrustZone secure/non-secure regions and veneers

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T044** from
`Embedra-SpecKit.md`:

> T044 Implement TrustZone secure/non-secure region and veneer handling for
> supported devices.

Do **not** begin T045. Do not commit, push, or publish unless explicitly asked.

## 0. Read and validate first (stop on any mismatch)

Read, in order:

1. `.embedra/state.json`
2. `.embedra/evidence/tasks/T043.md`, `T042.md`, `T041.md`, `T040.md`, `T039.md`
3. `Embedra-SpecKit.md` (STM-004, STM-008, STM-009, STM-010, STM-011, STM-019,
   STM-020, and T044)
4. Existing STM32 region/topology and vector code under
   `io.github.rezabakhshi.embedra.targets.stm32.*`, the T039 memory plans
   (`catalogs/stm32/2026-09-29/memory-plans.json`), the T040/T041/T042 packs, and
   the curated catalog's `securityEvidence`/`securityStatus` fields.

Verify before writing code:

- `sh scripts/validate-handoff.sh` and `sh scripts/validate-fixture-provenance.sh` pass.
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0 with `readyCount 53/53`.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state.
- Record the T043 reproducible ZIP digest and size from state; if the working
  tree differs, re-run `scripts/verify-build-quality.sh` before relying on it.

If anything disagrees, report the discrepancy and stop instead of guessing.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: security-domain planning, attribution, and
  veneer modeling stay under `targets`/`analyzers`; Ghidra mutation stays under
  `ghidra`. Do not import Ghidra APIs into pure packages.
- STM-010: represent TrustZone secure/non-secure images and veneers explicitly
  **only for applicable devices that the pinned evidence supports**. Do not infer
  a security attribute from an application image, a family name, or a sibling
  part.
- STM-019: every exact STM32 part record keeps its explicit `PLANNED`,
  `EXPERIMENTAL`, `VERIFIED`, or `UNSUPPORTED` state. Verifying one family member
  never verifies a sibling part number. No support state is promoted by T044.
- Do not modify T039 memory plans, T040 device-data packs, T041 vector behavior,
  T042 board profiles, or the T043 signature packs.
- Never invent a security domain boundary, SAU/IDAU attribute, veneer address,
  NSC region, or boot address. Unavailable or ambiguous facts stay explicit and
  fail closed.
- Reuse the shared parser limits, pack manifest/integrity/provenance contracts,
  and cooperative cancellation.

## 2. Implement

1. **Security-domain model (pure).** Define immutable secure/non-secure region and
   domain facts per applicable exact part, derived only from pinned,
   redistributable ST/CMSIS/TrustZone evidence. Keep attribution, attributes
   (`S`/`NS`/`NSC`), and provenance explicit; a part with no pinned evidence
   stays unavailable with a reason.
2. **Veneer handling (pure).** Model secure/non-secure callable veneer boundaries
   and transitions without fabricating addresses or instruction semantics. A
   match is evidence-backed and never establishes device support.
3. **Composition and validation.** Compose with the existing T039 memory plan and
   topology without mutating it; fail closed on overlap, missing evidence,
   unsupported cores, or ambiguous domains.
4. **Integration and provenance.** Add or extend a digest-pinned snapshot and
   update `THIRD_PARTY_NOTICES.md`; wire any Ghidra application step
   transactionally, idempotently, and user-preservingly only if it is in scope
   and real-Ghidra tested. Do not fabricate a version-to-part link.

## 3. Tests (test-first, meaningful)

- Pure unit tests: model invariants, exact-part applicability/unavailability,
  composition immutability, overlap/ambiguity fail-closed, and malformed input.
- Malformed/boundary tests: truncated, oversized, duplicate, out-of-range, and
  unknown-domain records.
- Real-Ghidra integration tests if an adapter is added: transactional apply,
  rollback, idempotence, preservation, non-resurrection, and no-mutation on
  ambiguity.
- Keep the STM32/ESP Python suites green; record optional-source skips exactly.

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

- Add `.embedra/evidence/tasks/T044.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T044`,
  real exit status, result, artifacts).
- Update `.embedra/state.json`: check T044 complete, add it to `completedTasks`,
  set `nextTask` to T045 and the matching unchecked SpecKit task, update test
  counts, working tree, and artifacts with the new ZIP digest.
- Check the T044 box in `Embedra-SpecKit.md` and update the spec digest in state.
- Update `PROJECT_STATE.md` and the next handoff prompt `.embedra/prompts/T045-*.md`.
- Do not modify T039-T043 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for a security-domain source, the only available links are family or
wildcard inference, or implementing T044 would require mutating T039-T043 data.
