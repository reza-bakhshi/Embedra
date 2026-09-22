# Foundation Acceptance Gate

## Result

`PASS`

Date: 2026-09-22. Maintainer approval: `PENDING`.

## Completed Tasks

T001, T002, T003, T004, T005, T006, and T007.

## Gate Criteria and Evidence

- Pure core builds without Ghidra: `clean pureTest` passed with `GHIDRA_INSTALL_DIR` absent; 12 actions executed.
- Pure/Ghidra isolation: architecture tests passed, including the negative forbidden-import fixture.
- Transaction skeleton: two real-Ghidra-API integration tests passed for default rollback, explicit commit, post-close rejection, and idempotent close.
- Canonical report: deterministic report/topology/catalog snapshots and locale/time-zone tests passed in the 60-test unit suite.
- Pack foundation: malformed, provenance, digest, path/symlink, cancellation/limits, atomic install, corruption, and offline selection tests passed.
- Fixture provenance: current repository validation plus synthetic positive/negative policy tests passed; no firmware fixture is committed.
- Agent continuity: current handoff validation and a specification-drift rejection test passed using repository files only.
- Clean configured regression: 18 actions executed successfully; 60 unit and 2 Ghidra integration tests passed with zero failures/errors/skips.
- Reproducible release ZIP: two configured clean builds were byte-identical; exact outer/source contents and integrity passed.

## Commands and Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`.
- Java: OpenJDK 21.0.12, 64-bit.
- Gradle Wrapper: 9.6.1.
- Ghidra: 12.1.3 PUBLIC, build date 2026-08-17, revision `8b4c91d4d5bd1549622bfbade0df199585b98365`.
- `env -u GHIDRA_INSTALL_DIR ... ./gradlew --offline --no-daemon --rerun-tasks clean pureTest`: PASS, 12/12 actions executed.
- `sh scripts/validate-fixture-provenance.sh`: PASS.
- `sh scripts/validate-handoff.sh`: PASS.
- `./gradlew --offline --no-daemon --rerun-tasks -P<ghidra> clean check jacocoTestReport jacocoTestCoverageVerification ghidraIntegrationTest buildExtension`: PASS, 18/18 actions executed.
- `scripts/verify-build-quality.sh`: PASS, byte-identical builds, exact contents.

## Requirements and Fixtures Covered

- Constitutions I–XI as applicable to the foundation, particularly pure-core isolation, evidence, non-destructive transactions, reproducibility, provenance, task order, honest execution, and pinned inputs.
- `CORE-002`–`CORE-007`, `CORE-008`, `CORE-010`, `CORE-013`, `CORE-017`–`CORE-021` foundation contracts.
- `TOPO-001`–`TOPO-005` immutable topology/reporting contracts.
- Synthetic fixtures only: checked range/reader bytes, topology/report/catalog snapshots, pack directories/manifests, forbidden-import source, fixture-policy positive/negative temporary files, and handoff drift copy. No firmware/device compatibility fixture or claim.

## Artifact and Coverage

- Extension ZIP: `dist/ghidra_12.1.3_PUBLIC_20260922_Embedra.zip`.
- Size: 151,328 bytes.
- SHA-256: `9b8900a3f66d1552a9b0e3f89e83c8f6edb5bd489e12a8745876f1ce9cc7a200`.
- Core branch coverage: 99.55%; minimum measured core class remains 92.86%.
- Pack coverage: 92.26% instructions, 77.59% branches; review remains explicitly assigned to T070.

## Compatibility Claims Earned

- Local Linux x86-64 build/test/package compatibility with OpenJDK 21.0.12 and the supplied official Ghidra 12.1.3 distribution.
- Pure unit/quality suite can run without Ghidra.
- The transaction wrapper compiles and behaves against Ghidra 12.1.3's `Program` API.
- The extension ZIP is locally reproducible for the recorded inputs.
- No firmware format, processor, device, board, catalog record, GUI workflow, or headless import is claimed supported.

## Known Limitations and Risks

- The committed GitHub workflow is locally syntax/policy tested but has not executed on a hosted runner here.
- No firmware fixtures exist yet; T008 begins fixture work only after approval.
- The transaction skeleton does not prove rollback for loaders or multi-program workspaces that are not implemented.
- Pack publisher authenticity/signing, fixture schema/evidence indexing, archive adversarial tests, broad coverage review, SBOM/signing, and release compatibility matrices remain later tasks.
- T006 and T007 changes are uncommitted and are recorded as such; baseline Git commit is `2314e4488ffb5f2c7d7b25bb392883c760539040`.

## Approval Boundary

Implementation is stopped. T008 must not begin until the maintainer explicitly approves this `PASS` after reviewing the gate report.
