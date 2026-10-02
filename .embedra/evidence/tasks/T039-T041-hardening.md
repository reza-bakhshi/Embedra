# T039–T041 hardening review and addendum

## Scope

An independent T039–T041 review (2026-10-02) examined the memory planner, the
CMSIS-SVD device-data transform/loader/applicator, and the vector-label
applicator. The high-severity, independently reproduced findings were fixed
before T042 began. Shipped curated data, memory plans, packs, applicability,
support states, and the spec checkpoint are unchanged.

## Verified findings and resolutions

| # | Task | Finding | Resolution |
|---|---|---|---|
| H1 | T041 | `Stm32VectorLabelApplicator` accepted any exact-part interrupt entry without binding it to the program (an F103 image could receive an F401 interrupt list). | The adapter reads the exact part recorded by the raw-import, SVD, interrupt, and vector-label provenance namespaces and fails closed with `PACK_INCOMPATIBLE` on disagreement. Regression added. |
| H2 | T040 | The same missing program-level binding existed in `Stm32SvdApplicator`. | The applicator's `begin` now applies the same recorded-part check for registers, interrupts, and combined application. Regression added. |
| H3 | T040 | `generate-stm32-svd-packs.py` rejected DTD/entities with a raw byte substring that UTF-16/UTF-32 input bypasses, and entity expansion ran before the complexity budget. Reproduced: a UTF-16 document with an internal entity parsed and expanded. | `ensure_safe_xml` strips an optional UTF-8 BOM, rejects UTF-16/UTF-32 BOMs and NUL-bearing heads, decodes UTF-8 strictly, and scans decoded text for `<!DOCTYPE`/`<!ENTITY` before parsing. UTF-16 regressions added. |
| H4 | T040 | `Stm32SvdPackLoader.peripheral` converted interrupt values outside the try; an out-of-int-range value escaped as unchecked `ArithmeticException`. `Stm32InterruptPlan.load` had the same gap. | The loader converts inside a guarded block and the interrupt plan catches `ArithmeticException`, both yielding typed `PACK_CONTENT_INVALID`/`IOException`. Loader regression added. |
| H5 | T040 | `Stm32SvdRegister` did not reject overlapping fields or duplicate field names, and `Stm32SvdField` did not reject duplicate enumerated value names; the integrity boundary relied on the generator. | Model constructors now reject all three, and the loader inherits the checks. Model regressions added. |
| H6 | T039 | `configurationPlaceholder` reported the min/max bounding box across all allocations. For H735 that was `0x10000..0x24050000` (604,241,920 bytes) while the declared bank is 192 KiB. | The placeholder anchors at the minimum allocation start and is sized by `physicalKiB`, rejecting a missing/overflowing size. H735 regression asserts the 192-KiB extent and that it does not reach the AXI region. |
| H7 | T039 | `generate-stm32-memory-candidates.py` used the same encoding-bypassable raw-byte DTD/entity check. | Replaced with the same encoding-safe decode/scan; UTF-16 regression added. |

## Verification

| Command | Result |
|---|---|
| `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> ./gradlew check verifyFormatting --no-daemon` | PASS: 262 unit, 93 real-Ghidra tests; Checkstyle, JaCoCo, formatting, STM32 catalog/fixture, ESP catalog, scaffold checks |
| `python3 -m unittest discover -s scripts/tests -p 'test_*stm32*.py'` | 105 STM32 Python tests, `OK (skipped=2)` |
| `python3 -m unittest scripts/tests/test_generate_esp_catalog.py` | 4 ESP Python tests, OK |
| `python3 scripts/audit-stm32-memory-readiness.py --require-complete` | exit 0; `readyCount 53/53` |
| `JAVA_HOME=<jdk21> GHIDRA_INSTALL_DIR=<ghidra-12.1.3> scripts/verify-build-quality.sh` | PASS: two clean, uncached 22-action builds; byte-identical 3,967,956-byte ZIP SHA-256 `47b41bd8b6712be329a7f4b8c516c8f685cbc99d93ff4e7446536ed5fbbd7460` |
| `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` | PASS |

## Residual hardening backlog (documented, not blocking)

The review also identified lower-severity items that were not changed by this
pass, to avoid altering accepted T039/T040 semantics without a dedicated task:

- T040 applies SVD labels/types/comments additively inside a user-preserved
  peripheral block after recording `MEMORY_PRESERVED`; this is a documented
  design choice, not a silent overwrite.
- Non-enumerated fields wider than 32 bits are not currently materialized by the
  applicator (`UnsignedIntegerDataType`); the shipped packs contain none, and
  the deferred-part path should choose a width-appropriate base type.
- Register-level `modifiedWriteValues`, array registers with no substitution
  placeholder, and `createdEnumerations` over-counting on reapply.
- The remaining STM32 source-research generators (`generate-stm32-catalog.py`,
  `generate-stm32-dfp-catalog.py`, `generate-stm32-svd-rules.py`) and the
  ESP32-S3 SVD generator use raw byte-substring DTD/entity checks; they operate
  on digest-pinned build-time sources, not runtime packs.
- T039's Java planner does not yet assert `topology.physicalCoreCount` (the
  Python audit does), and malformed IPCC/HSEM bounds surface as an NPE rather
  than a typed rejection.

No support state is promoted and no exact-part or family inference is added.
