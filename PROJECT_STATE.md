# Embedra Project State

## Status

- Project classification: new project; no prior implementation or valid handoff existed.
- Current task: **T005 — READY**.
- Last completed task: **T004**.
- Acceptance gates: none run.
- Version control: Git repository on branch `main`; the repository snapshot identifies its revision as `HEAD`.
- Specification: `Embedra-SpecKit.md`, SHA-256 `414f22a911d59afe19a8177802c7e0e8e6d38b102ea55f078ee4db2296553161`.

## Verified Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`.
- Ghidra: supplied distribution reports `12.1.3 PUBLIC`, build date `2026-08-17`, Java compiler/minimum `21`, Gradle minimum `8.5`.
- Gradle: Ghidra-supplied wrapper pins `9.6.1`; that distribution is locally cached and starts successfully.
- Java verified: OpenJDK `21.0.12`, 64-bit; the required baseline is satisfied.
- Negative compatibility check: JDK 25 is rejected with a specific early diagnostic.
- Build quality: JUnit `6.1.3`, JaCoCo `0.8.15`, Checkstyle `14.1.0`; resolved dependencies are locked.

## Completed Work

T001 through T004 are complete. The pure core now provides checked half-open source/address ranges, bounded little-endian reads, cooperative cancellation, centralized parser limits, typed stable diagnostics, evidence/confidence, and validated execution-topology models. The topology distinguishes instruction-bearing processors from fixed hardware and records security domains, symmetric/alternative groups, shared memory/aliases, boot/reset relationships, communication links, and shared-versus-separate-program strategy. The final uncached offline regression executed all 14 actionable tasks successfully; all 28 tests passed. Current core branch coverage is 129/130 (99.23%), with every covered core class at or above 92.86%. Two clean builds produced byte-identical 56,108-byte ZIPs with SHA-256 `07d158876bc8379360bbd25bd504fac1652614e8581f5e2ba3349f7a7cc7f198`. No foundation acceptance gate occurs until T007.

## Changed Files

- Added range, bounded-reader, cancellation, parser-limit, diagnostic, evidence, confidence, and topology production models under the pure core.
- Added 23 T004 tests covering successful, boundary, malformed, overflow, cancellation, resource-limit, and topology-reference behavior.
- Documented core invariants/defaults and added ADR 0003; no dependency, vendor data, firmware fixture, or device-support claim was introduced.
- Marked T004 complete and updated mandatory continuity/evidence records.

No firmware parser, provider, device data, fixture, catalog, or support claim was added.

## Exact Next Action

Begin T005 by reporting its deterministic schema/snapshot requirements and expected files, then write failing tests for canonical report ordering/schema identity, device-catalog snapshot/diff behavior, execution-topology reporting, and stable snapshot helpers. Do not begin T006 until T005 is complete.
