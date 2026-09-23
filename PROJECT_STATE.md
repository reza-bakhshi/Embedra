# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T026 — authoritative ESP catalog (`COMPLETE`)**.
- Last completed task: **T026**.
- Acceptance gates: Foundation `PASS`/approved; ESP32-S3 application `PASS`/approved; ESP32-S3 full flash review 2 `PASS`/approved on 2026-09-23.
- Version control: T023-T024 and their continuity handoff are committed on branch `main` at `90ea517`; T025 and gate-review remediation are uncommitted.
- Specification: `Embedra-SpecKit.md`; digest is recorded in `.embedra/state.json`.

## Verified Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`.
- Ghidra: supplied distribution reports `12.1.3 PUBLIC`, build date `2026-08-17`, Java compiler/minimum `21`, Gradle minimum `8.5`.
- Gradle: Ghidra-supplied wrapper pins `9.6.1`; that distribution is locally cached and starts successfully.
- Java verified: OpenJDK `21.0.12`, 64-bit; the required baseline is satisfied.
- Negative compatibility check: JDK 25 is rejected with a specific early diagnostic.
- Build quality: JUnit `6.1.3`, JaCoCo `0.8.15`, Checkstyle `14.1.0`; resolved dependencies are locked.
- ESP fixture tools: Espressif `xtensa-esp-elf` `esp-15.2.0_20251204`; esptool `5.4.0`; ESP-IDF v6.0 reference revision `662a3be354759d9487bf4b1a629fadb766cb1800`.
- ESP SVD input: official Apache-2.0 Espressif SVD revision `be20aa12560889d6125d144cdb48cf615ac17628`.

## Completed Work

T001 through T025 are complete. Gate-review remediation adds a hardened bounded
SVD parser/generator, a provenance-checked ESP32-S3 SVD pack, import-selectable
ROM/peripheral/SVD application, field-aware Ghidra register types and comments,
and conservative hardware/ROM crypto bookmarks with explicit unsupported
coverage. The maintainer approved the revised ESP32-S3 full-flash gate and T026
completed the authoritative offline ESP catalog with 53 silicon variants, 161
module profiles, and 58 board profiles. All new records remain `PLANNED` and
overall ESP32-S3 support remains `EXPERIMENTAL`.

## Changed Files

- Added T015 loader, transactional mapper, stable mapping failure codes, entry application, and immutable import report.
- Added T016 optional app-description model/extractor and golden, absent, truncated, malformed, provenance, and immutability tests.
- Added T017 shared import service, canonical mapping snapshots/reports, loader delegation, workflow-equivalence and malformed no-mutation tests, deterministic fuzz campaign, ADR, task evidence, and gate evidence.
- Added T018 CSV sources, deterministic full-flash generator, four fixture/manifests, ESP-IDF oracles, fixture tests, and documentation.
- Added T019 immutable flash/table/entry models, bounded discovery and validation, stable diagnostics, and malformed/limit/cancellation tests.
- Added T020 immutable workspace/extraction models, exact embedded-image boundary validation, separate-program loader behavior, persistent flash provenance, tests, ADR, and user documentation.
- Added T021 handler/inspection/OTA models, explicit registry, erased-slot planning, RTC-data mapping, restricted-dump tests, ADR, and documentation.
- Added T022 content schemas, pinned deterministic generator, ROM/peripheral packs, integrity-first loaders/models, transactional Ghidra applicator/removal receipts, real-Ghidra tests, ADR, notices, and documentation.
- Added T023 immutable enrichment facts/results, metadata/log/FreeRTOS/signature analyzer, strict evidence distinctions, limits/cancellation tests, ADR, and support documentation.
- Added T024 immutable security evidence/results, ESP32-S3 RSA V2 structure scanner, image-hash and partition/NVS indicators, unavailable-eFuse safeguards, tests, ADR, and documentation.
- Added T025 immutable artifact/diff/finding models, bounded analyzer, redaction and false-positive tests, ADR, documentation, and the ESP32-S3 full-flash gate report.
- Added review remediation with 54 SVD peripherals, 4,283 registers, 11,769
  fields, 42 peripheral-base and 1,530 register-address cross-checks, explicit
  import wiring, Ghidra structures/comments/bookmarks, and ADR 0018.
- Added T026 bounded official-product ingestion, pinned normalized facts,
  generated ESP catalog/schema, exact-variant resolver, shared catalog
  projection, explicit networked drift CI, tests, documentation, and ADR 0019.
- Clean verification passed 140 unit and 22 real-Ghidra tests plus 4 Python
  generator tests; reproducible ZIP SHA-256 is
  `5e764521fb3fefb7fdda20256fdb7af4db89a799647b05f22c4f441ac6c51dbc`.
- T001-T024 implementation is committed; T025, review-2 gate, and T026 work are uncommitted.
  Restricted `esp32s3_ctf_dump_4MB.bin` remains ignored and untracked. The
  transient untracked `flash_dump.bin` caught by the package oracle is now
  absent; its ignore and package-exclusion safeguards remain.

No complete device catalog, exact variant, board, or hardware support claim was added.

## Exact Next Action

Begin T027 by reporting its shared-behavior/topology prerequisites and writing
the failing common-service tests. Do not begin T028 until T027 is complete.
