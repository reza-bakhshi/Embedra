# ESP32-S3 Full-Flash and Enrichment Acceptance Gate

## Result

`PASS`

Date: 2026-09-23. Maintainer approval: `PENDING`.

## Completed Tasks

T018, T019, T020, T021, T022, T023, T024, and T025.

## Gate Criteria and Evidence

- Partition results for default factory, custom-offset, OTA/custom/encrypted,
  and invalid-MD5 images are checked against retained ESP-IDF CSV/tool oracles.
- Default-offset preference, bounded custom-offset discovery, invalid MD5
  rejection, and misleading embedded magic negatives pass.
- Bootloader and populated factory/OTA images remain separate programs with
  exact flash provenance; erased slots remain non-program artifacts.
- Explicit handlers cover OTA state, NVS, NVS keys, PHY, coredump, FAT, SPIFFS,
  LittleFS, custom, encrypted, and inactive application partitions.
- The digest-pinned restricted 4 MiB user capture passes pure parsing and real
  ProgramDB import without being committed or packaged.
- Provenance-checked ESP32-S3 ROM/peripheral packs, semantic enrichments,
  security evidence, and factory/OTA diff/CTF leads pass their positive,
  negative, limit, cancellation, immutability, and preservation tests.
- Clean regression passed 128 unit and 17 real-Ghidra tests with no failures,
  errors, or skips. Reproducible packaging and fixture provenance passed.

## Commands and Environment

- Linux x86-64, kernel `7.0.0-31-generic`
- OpenJDK 21.0.12; Gradle Wrapper 9.6.1
- Ghidra 12.1.3 PUBLIC, build date 2026-08-17, revision
  `8b4c91d4d5bd1549622bfbade0df199585b98365`
- esptool 5.4.0; compiler `esp-15.2.0_20251204`; ESP-IDF v6.0 revision
  `662a3be354759d9487bf4b1a629fadb766cb1800`
- Clean `--rerun-tasks clean check ... buildExtension`: PASS, 19/19 actions
- `scripts/verify-build-quality.sh`: PASS, byte-identical output
- Fixture provenance and restricted/package inspections: PASS

## Requirements and Fixtures Covered

CORE-001 through CORE-010 as applicable, CORE-012 through CORE-020 as
applicable, ESP-007 through ESP-014, US2, US3, and relevant US8 behavior.
Fixtures include all four redistributable T018 full-flash images and the local
restricted capture identified only by sanitized metadata and SHA-256
`837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de`.

## Artifact and Compatibility Claims Earned

- ZIP: `dist/ghidra_12.1.3_PUBLIC_20260923_Embedra.zip`
- Size: 478,775 bytes
- SHA-256: `df78f9c8cf51cb5fec7531ec88f299aca01aa01077d11e53f9e5397ffa311faf`
- Experimental ESP32-S3 raw full-flash analysis on the recorded environment:
  validated partition discovery, extraction, separate-program planning/import,
  explicit data handlers, offline enrichment, and conservative findings.
- This does not verify every ESP32-S3 silicon/package/flash/PSRAM/module/board,
  hardware behavior, eFuse state, or another ESP family member.

## Known Limitations and Risks

- The only real-world dump is user-supplied with unknown provenance and remains
  restricted; public CI uses deterministic synthetic fixtures.
- Filesystem contents needing build-time parameters, NVS values, cryptographic
  signature verification, production library signatures, and desktop GUI
  automation remain incomplete or later work.
- Exact ESP variants and the rest of the ESP family require T026-T031 and
  independent evidence; no family-wide support claim is earned.

## Approval Boundary

Implementation is stopped. T026 must not begin until the maintainer explicitly
approves this `PASS` gate.
