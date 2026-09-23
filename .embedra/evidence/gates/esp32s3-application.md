# ESP32-S3 Application-Image Acceptance Gate

## Result

`PASS`

Date: 2026-09-23. Maintainer approval: `APPROVED` on 2026-09-23.

## Completed Tasks

T008, T009, T010, T011, T012, T013, T014, T015, T016, and T017.

## Gate Criteria and Evidence

- Exact segments: the T008 esptool/ELF oracle and T014/T015 real ProgramDB tests
  agree on all encoded addresses, lengths, bytes, DROM/DRAM/IRAM classes, and
  R/RW/RX permissions.
- Exact entry: `0x40378000` is accepted only inside the mapped executable IRAM
  segment for `Xtensa:LE:32:default`; the imported entry symbol and external
  entry point are verified.
- Corrupt-image rollback/no mutation: the complete T009 corpus returns exact
  typed failures before mutation, and mapping conflicts preserve pre-existing
  user blocks without partial segments or entries.
- Loader detection is byte-validated and does not infer targets from filenames.
- Optional app metadata is bounded and non-fatal with exact source/target
  provenance.
- GUI/headless loader behavior converges on one service; independent ProgramDB
  runs under different caller names, locales, and time zones emit byte-identical
  canonical reports and program snapshots.
- The deterministic 512-case campaign has the retained outcome digest
  `8f35791f21d7f0b875d7c094657a768ba29aa38a725dda13242474242a113d23`.

## Commands and Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`.
- Java: OpenJDK 21.0.12, 64-bit.
- Gradle Wrapper: 9.6.1.
- Ghidra: 12.1.3 PUBLIC, build date 2026-08-17, revision
  `8b4c91d4d5bd1549622bfbade0df199585b98365`.
- ESP fixture references: esptool 5.4.0, ESP-IDF v6.0 revision
  `662a3be354759d9487bf4b1a629fadb766cb1800`, and Espressif compiler
  `esp-15.2.0_20251204`.
- Targeted T017 unit/integration suite: PASS.
- `./gradlew --offline --no-daemon pureTest`: PASS.
- `scripts/verify-build-quality.sh`: PASS twice from clean build directories,
  with byte-identical extension output.
- Fixture provenance, handoff, JSON/JSONL, and whitespace validators: PASS.

## Requirements and Fixtures Covered

- CORE-001 through CORE-003, CORE-011, CORE-015, CORE-016, CORE-020.
- ESP-001 through ESP-006 and US1/US9 behavior applicable to application images.
- Both T008 golden application images and every T009 malformed image.
- Detector/parser/model, checksum/digest, target/provider, language/memory/entry,
  transactional mapper, loader, optional metadata, canonical output, shared
  workflow, and deterministic mutation coverage.

## Artifact and Compatibility Claims Earned

- Extension ZIP: `dist/ghidra_12.1.3_PUBLIC_20260923_Embedra.zip`.
- Size: 233,577 bytes.
- SHA-256:
  `8925028d39cc9c04612d069de6ebd67d66aa93f5ca96b459d0d9f65d72f58864`.
- Verified application-image capability for encoded ESP images declaring chip
  ID 9, using the tested ESP32-S3 provider and Ghidra language/compiler pair on
  the recorded Linux/JDK/Ghidra environment.
- This is an application-image format/provider claim, not blanket verification
  of ESP32-S3 part, package, flash, PSRAM, module, board, or hardware variants.

## Known Limitations and Risks

- Desktop click/UI automation and other host platforms/Ghidra releases remain
  unclaimed; the test proves equality at the common Ghidra loader workflow.
- Fuzzing is deterministic bounded mutation coverage, not exhaustive or
  coverage-guided fuzzing.
- Full-flash/partition support begins only at T018 after approval.
- The complete Espressif catalog and exact silicon/module/board identities are
  deferred to T026 and later independent verification tasks.
- T014-T017 work is uncommitted and recorded in the repository handoff.

## Approval Boundary

The maintainer explicitly approved proceeding with T018-T020 on 2026-09-23.
The gate no longer blocks T018.
