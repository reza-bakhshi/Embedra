# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T006 — READY**.
- Last completed task: **T005**.
- Acceptance gates: none run.
- Version control: Git repository on branch `main`; T005 is saved in the current `HEAD` commit.
- Specification: `Embedra-SpecKit.md`, SHA-256 `559df024bec02e083b522bd36fcc0b6141bdb46d97e3cbedd65193a0ce6de96e`.

## Verified Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`.
- Ghidra: supplied distribution reports `12.1.3 PUBLIC`, build date `2026-08-17`, Java compiler/minimum `21`, Gradle minimum `8.5`.
- Gradle: Ghidra-supplied wrapper pins `9.6.1`; that distribution is locally cached and starts successfully.
- Java verified: OpenJDK `21.0.12`, 64-bit; the required baseline is satisfied.
- Negative compatibility check: JDK 25 is rejected with a specific early diagnostic.
- Build quality: JUnit `6.1.3`, JaCoCo `0.8.15`, Checkstyle `14.1.0`; resolved dependencies are locked.

## Completed Work

T001 through T005 are complete. The pure core now also provides a restricted deterministic JSON writer; versioned canonical-report, execution-topology, exact-device catalog snapshot, and catalog-diff contracts; and immutable golden-snapshot assertions. Reports include inputs, providers/packs, validations, mappings, applied symbols/types with provenance, metadata, topology, findings, diagnostics, and explicit reproducibility settings without host paths or timestamps. Catalog entries retain an explicit per-capability support state and diff only exact device identities. The final uncached offline regression executed all 15 actionable tasks successfully; all 41 tests passed. Current core branch coverage is 99.55%, with every core class containing branches at or above 92.86%. Two clean builds produced byte-identical 103,934-byte ZIPs with SHA-256 `aa6693eb56ea34c222cb8c5741a8e112a68d6c31b0d25f71feeb595bc246f229`. No foundation acceptance gate occurs until T007.

## Changed Files

- Added deterministic report and catalog production contracts under `core/report` and `core/catalog`.
- Added four closed JSON Schema 2020-12 documents, packaged them inside the extension JAR, and added 13 T005 tests plus two reviewed golden snapshots.
- Documented canonicalization and catalog semantics and added ADR 0004; no dependency, vendor data, firmware fixture, catalog snapshot, or device-support claim was introduced.
- Marked T005 complete and updated mandatory continuity/evidence records.

No firmware parser, provider, device data, fixture, catalog, or support claim was added.

## Exact Next Action

Begin T006 by reporting its pack-manifest, digest, provenance, local-installation, and offline-selection requirements and expected files. Write failing tests for valid/malformed manifests, digest mismatch, provenance/license rejection, traversal-safe local installation, deterministic offline selection, and missing/incompatible packs before production implementation. Do not begin T007 until T006 is complete.
