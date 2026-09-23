# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T022 — COMPLETE; T023 is next**.
- Last completed task: **T022**.
- Acceptance gates: Foundation `PASS`/approved; ESP32-S3 application `PASS`/approved on 2026-09-23.
- Version control: T009-T013 are committed on branch `main` with handoff commit `3468842`; T014-T022 are uncommitted.
- Specification: `Embedra-SpecKit.md`; digest is recorded in `.embedra/state.json`.

## Verified Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`.
- Ghidra: supplied distribution reports `12.1.3 PUBLIC`, build date `2026-08-17`, Java compiler/minimum `21`, Gradle minimum `8.5`.
- Gradle: Ghidra-supplied wrapper pins `9.6.1`; that distribution is locally cached and starts successfully.
- Java verified: OpenJDK `21.0.12`, 64-bit; the required baseline is satisfied.
- Negative compatibility check: JDK 25 is rejected with a specific early diagnostic.
- Build quality: JUnit `6.1.3`, JaCoCo `0.8.15`, Checkstyle `14.1.0`; resolved dependencies are locked.
- ESP fixture tools: Espressif `xtensa-esp-elf` `esp-15.2.0_20251204`; esptool `5.4.0`; ESP-IDF v6.0 reference revision `662a3be354759d9487bf4b1a629fadb766cb1800`.

## Completed Work

T001 through T022 are complete. T022 adds two provenance/integrity-checked offline ESP32-S3 enrichment packs generated deterministically from pinned ESP-IDF v6.0: 2,197 ROM symbols and 61 peripheral windows with 2,173 register addresses/aliases. The Ghidra applicator is transactional, idempotent, conflict preserving, and receipt-removable. Overall ESP32-S3 support remains `EXPERIMENTAL` because exact catalog variants and physical hardware verification are incomplete.

## Changed Files

- Added T015 loader, transactional mapper, stable mapping failure codes, entry application, and immutable import report.
- Added T016 optional app-description model/extractor and golden, absent, truncated, malformed, provenance, and immutability tests.
- Added T017 shared import service, canonical mapping snapshots/reports, loader delegation, workflow-equivalence and malformed no-mutation tests, deterministic fuzz campaign, ADR, task evidence, and gate evidence.
- Added T018 CSV sources, deterministic full-flash generator, four fixture/manifests, ESP-IDF oracles, fixture tests, and documentation.
- Added T019 immutable flash/table/entry models, bounded discovery and validation, stable diagnostics, and malformed/limit/cancellation tests.
- Added T020 immutable workspace/extraction models, exact embedded-image boundary validation, separate-program loader behavior, persistent flash provenance, tests, ADR, and user documentation.
- Added T021 handler/inspection/OTA models, explicit registry, erased-slot planning, RTC-data mapping, restricted-dump tests, ADR, and documentation.
- Added T022 content schemas, pinned deterministic generator, ROM/peripheral packs, integrity-first loaders/models, transactional Ghidra applicator/removal receipts, real-Ghidra tests, ADR, notices, and documentation.
- T014-T022 changes are uncommitted; T009-T013 remain committed.

No complete device catalog, exact variant, board, or hardware support claim was added.

## Exact Next Action

Start T023 test-first with ESP-IDF metadata, logging-call, FreeRTOS, and library-signature enrichment contracts. Reuse the T022 pack/provenance and conflict-preserving application boundaries; do not infer an IDF version or signature match without bounded evidence.
