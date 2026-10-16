# ESP Family Full-Flash Expansion Acceptance Gate Report

## Result

`PASS`

Date: 2026-10-13. Maintainer approval: `APPROVED`.

This immutable gate report records the acceptance verification of the ESP32-branded full-flash
expansion workstream (T080–T087) as specified in `Embedra-SpecKit.md` Section 12.

## 1. Completed Tasks Covered

- **T080**: Official catalog, bootloader offset, partition table, MMU mapping, and architectural audit
  across all 14 ESP32-branded series (`docs/esp-full-flash-audit.md` and `.embedra/evidence/tasks/T080-capability-matrix.json`).
  Segregation of legacy ESP8266 preserved.
- **T081**: Independently generated, redistributable full-flash goldens, custom layouts, and official-tool
  oracles for all 14 series (`scripts/generate-esp-full-flash-fixtures.py`).
- **T082**: Refactored partition table discovery and workspace planner behind pure provider contracts
  (`EspFlashLayoutProfile`, `EspFlashLayoutProvider`, `EspFlashLayoutRegistry`).
- **T083**: Implemented target-aware capture identification and bounded workspace planning for original
  ESP32 (chip ID 0, bootloader `0x1000`) and ESP32-S2 (chip ID 2, bootloader `0x0000`).
- **T084**: Implemented and verified full-flash paths for all 8 standard RISC-V series (`ESP32-C3`,
  `ESP32-C2`, `ESP32-C5`, `ESP32-C6`, `ESP32-C61`, `ESP32-H2`, `ESP32-H21`, `ESP32-H4`).
- **T085**: Implemented and verified full-flash paths for `ESP32-P4`, `ESP32-S31`, and `ESP32-E22`. Recorded
  preliminary silicon documentation gaps for S31 and E22 per ESP-016 and ESP-027.
- **T086**: Wired all 14 proven target plans into real-Ghidra GUI and headless multi-program import
  (`EspFullFlashMultiProgramImportIntegrationTest`), verifying bootloader and application slot mapping,
  opaque artifact handling, cancellation rollback, repeat-import idempotence, and canonical equality.
- **T087**: Complete gate review, catalog drift verification, S3 baseline regression assertion, fixture/oracle
  provenance check, and license audit.

## 2. Pinned Specifications and Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`
- Ghidra: `12.1.3 PUBLIC`, build date `2026-08-17`
- Toolchain: OpenJDK `21.0.12` 64-bit; Gradle wrapper `9.6.1`
- Reference firmware tools: ESP-IDF v6.0 reference revision `662a3be354759d9487bf4b1a629fadb766cb1800`;
  esptool v5.4.0 (`gen_esp32part.py` 1.5)
- Catalog snapshot: `catalogs/espressif/2026-09-23/catalog.json` (SHA-256 `a012ee03ad12ec075b8b782cd8b3abd66cc236216cfe4001cf2c2a2a92990a00`)

## 3. Verified Compatibility Claims

1. **Full-Flash Capture Planning & Detection**:
   - Universal capture auto-detection at offset `0x0000` (and `0x1000` for ESP32) without prior user hints.
   - Bounded partition table discovery with sector alignment (`0x1000`) and partition table MD5 validation.
   - Safe extraction of second-stage bootloader and application executables (`factory`, `ota_0`, `ota_1`).
   - Opaque handling of non-executable partitions (NVS, PHY, storage, and encrypted ciphertext `assets`).

2. **Real-Ghidra Multi-Program Import**:
   - Multi-program workspace loading maps each executable into independent `Program` instances with
     correct architecture language IDs:
     - `Xtensa:LE:32:default` (`default`) for ESP32 and ESP32-S2.
     - `Xtensa:LE:32:esp32s3` (`default`) for ESP32-S3.
     - `RISCV:LE:32:default` (`gcc`) for all 11 RISC-V series (`C2`, `C3`, `C5`, `C6`, `C61`, `H2`, `H21`,
       `H4`, `P4`, `S31`, `E22`).
   - Immutable flash provenance persisted in `Embedra Full Flash Provenance` options per program.
   - Fail-closed error handling: invalid MD5, truncated images, and wrong-chip fixtures reject cleanly
     without creating partial or mutant programs.
   - Transactional rollback on failure and cooperative cancellation via `TaskMonitor` verified.
   - Canonical GUI/headless equality verified across divergent locales (`tr-TR` vs `ja-JP`) and
     timezones (`Asia/Tehran` vs `Pacific/Auckland`).

3. **Per-Exact-Variant & Preliminary Silicon Policy**:
   - All 53 exact silicon records across all 14 series retain explicit `PLANNED` state per ESP-018 and ESP-027.
   - Preliminary silicon parts (`ESP32-S31`, `ESP32-E22`) retain documented documentation gaps.
   - ESP8266 legacy Harvard format remains strictly segregated in `Esp8266LegacyImageLoader` and excluded
     from ESP32-branded full-flash planning.

## 4. Regression Assertion of ESP32-S3 Baseline

The previously approved ESP32-S3 application and full-flash gates (`esp32s3-application.md` and
`esp32s3-full-flash-r2.md`) were fully regression-tested:
- All original ESP32-S3 full-flash fixtures, oracles, SVD register applications, and crypto analyzer
  assertions pass 100% without modification or regression.
- Refactored `Esp32S3FlashLayoutProvider` preserves exact S3 address calculations and behavior.

## 5. Verification Sign-Off

- `./gradlew --offline --no-daemon check pureTest`: PASSED (all unit and real-Ghidra integration tests clean).
- `sh scripts/validate-fixture-provenance.sh`: PASSED (0 errors across all manifests).
- `python3 scripts/audit-licenses.py --check`: PASSED (114 third-party digests verified).
- `python3 scripts/scan-secrets.py`: PASSED (0 secrets leaked).
- `python3 scripts/check-documentation-links.py`: PASSED (0 broken links).
- `sh scripts/validate-handoff.sh`: PASSED (0 drift).
