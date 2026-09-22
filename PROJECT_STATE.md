# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T013 — COMPLETE**.
- Last completed task: **T013**.
- Acceptance gates: Foundation `PASS`; maintainer approval received on 2026-09-22.
- Version control: Git repository on branch `main` at commit `922a0d4`; T009-T013 work is uncommitted.
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

T001 through T013 are complete and the Foundation gate is `PASS` and approved. T012 retained the expected red provider compilation failure. T013 adds the pure ESP32-S3 target provider, provenance-bearing chip-ID 9 registry snapshot, exact Ghidra language/compiler selection, authoritative DROM/IROM/IRAM/DRAM classification, proposed permissions, and entry decisions requiring selected-language alignment plus containment in a mapped executable segment. The real Ghidra 12.1.3 language service resolves `Xtensa:LE:32:default`, compiler `default`, and instruction alignment 1. The clean regression passed 86 unit and 3 integration tests. Two builds produced the same 194,328-byte ZIP with SHA-256 `1f48bbb8fed564bb350e7644b3145e154db09730d4ddfb21b3272a69eb6ee983`. ESP32-S3 remains `EXPERIMENTAL`; no Ghidra segment mapping, exact silicon variant, board, or hardware claim is made.

## Changed Files

- Added T012 ESP32-S3 provider contract tests and retained their expected red compile result.
- Added T013 pure target decision models, ESP32-S3 provider, maintained chip-ID resource, malformed registry tests, and real Ghidra language-resolution integration coverage.
- Added ADR 0010 and an explicit `EXPERIMENTAL` support-matrix entry.
- T009-T013 fixture, parser/provider, test, documentation, and evidence changes remain uncommitted.

No loader, mapped Ghidra program, complete device catalog, exact variant, board, or hardware support claim was added.

## Exact Next Action

Begin T014 by reporting prerequisites and writing failing Ghidra segment-mapping and rollback tests against the T011 parser and T013 provider decisions. Do not implement T015 during T014.
