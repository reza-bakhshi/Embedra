# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T008 — COMPLETE**.
- Last completed task: **T008**.
- Acceptance gates: Foundation `PASS`; maintainer approval received on 2026-09-22.
- Version control: Git repository on branch `main` at baseline commit `2314e4488ffb5f2c7d7b25bb392883c760539040`; T006 through T008 are intentionally uncommitted.
- Specification: `Embedra-SpecKit.md`, SHA-256 `0b751b375d67a6bfcefa47b554af46df65c91393baade10eecdf4b8bf4731cf0`.

## Verified Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`.
- Ghidra: supplied distribution reports `12.1.3 PUBLIC`, build date `2026-08-17`, Java compiler/minimum `21`, Gradle minimum `8.5`.
- Gradle: Ghidra-supplied wrapper pins `9.6.1`; that distribution is locally cached and starts successfully.
- Java verified: OpenJDK `21.0.12`, 64-bit; the required baseline is satisfied.
- Negative compatibility check: JDK 25 is rejected with a specific early diagnostic.
- Build quality: JUnit `6.1.3`, JaCoCo `0.8.15`, Checkstyle `14.1.0`; resolved dependencies are locked.
- ESP fixture tools: Espressif `xtensa-esp-elf` `esp-15.2.0_20251204`; esptool `5.4.0`; ESP-IDF v6.0 reference revision `662a3be354759d9487bf4b1a629fadb766cb1800`.

## Completed Work

T001 through T008 are complete and the Foundation gate is `PASS` and approved. T008 adds two deterministic, redistributable ESP32-S3 application-image fixtures from an attributed Apache-2.0 freestanding source: digest-appended and no-digest variants. Retained esptool and ELF oracles cover chip ID 9, DROM/DRAM/IRAM segments, entry, checksum, digest, and application-description metadata. The generator builds twice, rejects byte drift, links no runtime, and keeps tools/caches outside the repository. The final uncached configured regression executed all 18 actions successfully; 61 unit and 2 integration tests passed. Two package builds were byte-identical and produced a 152,216-byte ZIP with SHA-256 `946b28123f7ff9b86ec21309a711f160f2dab24f254561dc1e1a7abfe79399d1`. No firmware/device compatibility is claimed.

## Changed Files

- Added freestanding ESP32-S3 fixture generator source and deterministic generation script.
- Added 432-byte digest and 400-byte no-digest golden images, adjacent provenance manifests, esptool snapshots, ELF snapshots, and canonical expectations.
- Added fixture evidence regression, ADR 0007, fixture-policy guidance, third-party attribution, and runtime-package exclusion for generator inputs.
- Marked T008 complete and recorded tool, fixture, command, licensing, corrective-failure, and regression evidence.

No firmware parser, provider, device catalog, loader, or support claim was added.

## Exact Next Action

Begin T009 by reporting its prerequisites and generating malformed ESP image fixtures for truncation, overflow, overlap, wrong-chip, checksum, digest, entry, and trailing-data cases. Do not begin T010 until T009 satisfies the Universal Definition of Done.
