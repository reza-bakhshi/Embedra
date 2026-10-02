# T043 Handoff Command — STM32 signature-pack generation and matching

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T043** from
`Embedra-SpecKit.md`:

> T043 Implement STM32 HAL/LL/CMSIS/startup/RTOS/library signature-pack
> generation and matching.

Do **not** begin T044. Do not commit, push, or publish unless explicitly asked.

## 0. Read and validate first (stop on any mismatch)

Read, in order:

1. `.embedra/state.json`
2. `.embedra/evidence/tasks/T042.md`, `T041.md`, `T040.md`, and `T039.md`
3. `Embedra-SpecKit.md` (STM-005, STM-012, STM-019 and T043)
4. Existing pack, provenance, and signature code under `src/main/java`,
   especially `io.github.rezabakhshi.embedra.pack.*`, the existing ESP FID
   manifests under `scripts/write-fid-manifests.py`, `fid/`, and any existing
   signature matcher; plus `catalogs/stm32/2026-09-29/*` and the STM32
   generators under `scripts/`.

Verify before writing code:

- `sh scripts/validate-handoff.sh` and `sh scripts/validate-fixture-provenance.sh` pass.
- `python3 scripts/audit-stm32-memory-readiness.py --require-complete` exits 0 with `readyCount 53/53`.
- `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in state.
- Record the T042 reproducible ZIP digest and size from state; if the working tree
  differs, re-run `scripts/verify-build-quality.sh` before relying on it.

If anything disagrees, report the discrepancy and stop instead of guessing.

## 1. Non-negotiable invariants

- Keep the pure/adapter boundary: signature-pack generation, parsing, integrity,
  and matching logic stay under `pack`/`analyzers`; Ghidra mutation stays under
  `ghidra`.
- STM-012: apply HAL/LL/CMSIS/startup/RTOS/library signatures only when
  compiler/optimization/family evidence is recorded. A signature match is
  evidence-backed and does not itself verify a device.
- STM-019: every exact STM32 part record keeps its explicit `PLANNED`,
  `EXPERIMENTAL`, `VERIFIED`, or `UNSUPPORTED` state per input format and feature.
  Verifying one family member never verifies a sibling part number.
- Do not modify T039 memory plans, T040 device-data packs, T041 vector behavior,
  the T042 board profiles, or any support state.
- Never invent a signature, library version, compiler identity, optimization
  level, or function-address mapping. Unavailable facts stay explicit and fail
  closed.
- Reuse the shared pack manifest/integrity/provenance contracts and the shared
  parser limits and cooperative cancellation.

## 2. Implement

1. **Signature-pack model and generator.** Define a digest-pinned, versioned,
   provenance-bearing signature pack (identity, exact/derived supported
   families and versions, license, source revision, transformation, and
   per-file size/SHA-256). Generator input must be a pinned, redistributable
   source; record every source revision and digest.
2. **Pure matching.** Implement a deterministic matcher that reports a match only
   when the recorded compiler/optimization/family evidence is present, and
   otherwise returns an explicit non-match with a stable diagnostic. Bound all
   scanning and reject malformed or oversized inputs.
3. **Integration.** Wire matching through the existing pack selection path and,
   if a Ghidra application step is added, apply names/comments transactionally
   and idempotently, preserving user artifacts and never resurrecting deleted
   ones.
4. **Catalog/provenance.** Add or extend a digest-pinned snapshot and update
   `THIRD_PARTY_NOTICES.md`; do not fabricate a version-to-part link.

## 3. Tests (test-first, meaningful)

- Pure unit tests: generator determinism, digest/provenance tampering, matcher
  positive/negative, missing-evidence non-match, malformed pack, and limits.
- Malformed/boundary tests: truncated, oversized, duplicate, and out-of-range
  entries; unknown family or version.
- Real-Ghidra integration tests if an adapter is added: preservation,
  idempotence, rollback, and no-mutation on ambiguity.
- Keep the STM32 Python suite green; add/extend generator tests and record
  optional-source skips accurately.

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

- Add `.embedra/evidence/tasks/T043.md` with scope, invariants, verification
  table, failures/skips, and remaining limitations.
- Append command evidence to `.embedra/evidence/commands.jsonl` (task `T043`,
  real exit status, result, artifacts).
- Update `.embedra/state.json`: check T043 complete, add to `completedTasks`, set
  `nextTask` to T044 and the matching unchecked SpecKit task, update test counts,
  working tree, and artifacts with the new ZIP digest.
- Check the T043 box in `Embedra-SpecKit.md` and update the spec digest in state.
- Update `PROJECT_STATE.md` and the next handoff prompt `.embedra/prompts/T044-*.md`.
- Do not modify T039/T040/T041/T042 artifacts or promote support states.

## 6. Stop conditions

Stop and report instead of proceeding if: pinned inputs are missing, the
SpecKit/state digest disagrees, a mandatory gate fails, provenance cannot be
established for a signature source, the only available links are family or
wildcard inference, or implementing T043 would require mutating T039-T042 data.
