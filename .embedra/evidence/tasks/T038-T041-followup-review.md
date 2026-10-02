# T038–T041 follow-up review and fixes

## Scope

A second independent T038–T041 audit (2026-10-02, after the T039–T041 hardening
pass and before T044) re-verified every T038–T041 claim: artifact digests,
catalog/applicability counts, shipped/deferred/unavailable partitions, exact-part
provenance namespaces, hardening fixes H1–H7, Python and Java suites, the
readiness audit, continuity validators, and the two-build reproducibility gate.
No curated data, memory plan, SVD pack, applicability decision, or support state
changed.

## Findings and resolutions

| # | Task | Finding | Resolution |
|---|---|---|---|
| R1 | T038 | `Stm32DevicePackRegistry.search` uppercased only the query, so curated `line` labels containing lowercase text (`STM32C0x1`, `STM32H750 Value line`) did not match case-insensitively, contradicting the class contract and the T038 evidence claim. | `search` normalizes `family` and `line` before matching; a regression covers a lowercase line query and mixed-case line resolution. |
| R2 | T040 | `svd/package-info.java` still documented the package as Espressif-only, while T040's changed-artifacts claim includes STM32 package documentation. | Package documentation now names Espressif and STM32 CMSIS-SVD models. |
| R3 | T040 | `Stm32BundledPacks.load` skipped only absent directories; a non-shipped applicability entry whose pack directory was present could load that pack instead of honoring the reviewed status. | Loading is restricted to `EXACT_SVD_SHIPPED` entries; a deferred entry whose pack exists now yields no pack. Regression added. |
| R4 | T039 | The evidence status cited the superseded correctness-pass ZIP `7f3c421b…` (state marks it `SUPERSEDED`) instead of the final allocation-resolution artifact `68a45831…`. | Status corrected to the final artifact. |
| R5 | T040 | `PROJECT_STATE.md` cited the pre-final T040 gate (`7b41324f…`, 83 real-Ghidra) while T040 evidence records the final review gate (`f04ee66e…`, 84). | PROJECT_STATE now cites the final review gate and notes the superseded pass. |
| R6 | continuity | `stm32SvdEnrichment.focusedVerification` counts lagged the current tests (`packLoaderTests` 4 vs 5, `ghidraApplicatorTests` 9 vs 10), and `unpairedCatalogFlashSizes: 0` sat unexplained next to the audit's `unresolvedFlash: 11`. | Counts updated; the 11 null catalog `flashKiB` fields and the validated plan coverage are now stated explicitly. |

No other code defect was found. The T040 out-of-int-range interrupt branch in
`Stm32InterruptPlan.load` remains unreachable under the pinned catalog digest
and therefore has no dedicated regression; it is defense-in-depth only.

## Verification

| Command | Result |
|---|---|
| `python3 scripts/audit-stm32-memory-readiness.py --require-complete` | exit 0; `readyCount 53/53`, `incompleteParts {}`, `unresolvedFlash 11` |
| `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'` | 123 tests, `OK (skipped=4)`: two absent pinned ST sources and two optional STM32Cube F1 regeneration checks |
| `python3 -m unittest scripts/tests/test_generate_esp_catalog.py` | 4 tests, OK |
| `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew test ghidraIntegrationTest --rerun-tasks --no-daemon` | 292 unit + 93 real-Ghidra tests, 0 failures/errors/skips |
| `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> scripts/verify-build-quality.sh` | PASS: two clean, uncached 22-action builds; byte-identical 4,186,433-byte ZIP SHA-256 `02cb3efad54d903d6f0e7b03de0a8b5053591047499a8766c6ab3baff18edb9b` |
| `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` | PASS |
| Artifact digests | `memory-plans.json` `00def2817b…`, `svd-applicability.json` `be795ab0…`, curated catalog `afc66a47…`, `selection.json` `1d4b971f…` unchanged |

## Preserved boundaries

- All 53 curated parts remain `PLANNED`; no support state is promoted.
- The curated catalog, T039 memory plans, T040 applicability and packs, T041
  vector behavior, T042 board profiles, and T043 signature packs are unchanged.
- No `.embedra`/state/evidence/prompt file is included in the extension ZIP.
