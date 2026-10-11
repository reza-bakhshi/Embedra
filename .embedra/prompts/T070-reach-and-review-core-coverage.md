# T070 Handoff Command — Reach and Review the Core Coverage Target

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T070** from `Embedra-SpecKit.md`:

> T070 Reach and review the core coverage target.

Do **not** begin T071. Do not commit, push, or publish unless explicitly asked.

---

## 0. Baseline to verify first (stop and report on any mismatch)

1. **Working Tree & Continuity**:
   - Working branch: `main`.
   - `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
   - `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in `.embedra/state.json` (`83febe416dd2e77f32cfa2abed893d32ef64c3cf57fcb46b89940521bc68919e`).
   - `state.currentTask.id` is `T069` (`COMPLETE`), and `state.nextTask` is `T070`.
   - In `Embedra-SpecKit.md`: checkboxes T001 through T069 are checked (`- [x]`), and T070 is unchecked (`- [ ] T070`).

2. **Toolchain & Pinned Environment**:
   - Java 21 baseline: `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64`.
   - Ghidra 12.1.3 PUBLIC baseline: `GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`.
   - Gradle wrapper: `./gradlew --offline --no-daemon`.

3. **Read in order**:
   - `.embedra/state.json` and `.embedra/evidence/tasks/T069.md`.
   - `Embedra-SpecKit.md` (T070 release gate, "Core parser branch coverage target: at least 90%, with reviewed exclusions").
   - `gradle/build-quality.gradle` (`jacocoTestCoverageVerification` configuration, rules, elements, includes/excludes).
   - JaCoCo test report: `build/reports/jacoco/test/jacocoTestReport.csv` and `build/reports/jacoco/test/html/index.html`.

---

## 1. Scope and Core Requirements for T070

Per `Embedra-SpecKit.md`:
- **Core Coverage Target**: "Core parser branch coverage target: at least 90%, with reviewed exclusions."
- **Evidence Contract**: "Coverage percentage alone is never acceptance evidence. Decompiler text is not a stable oracle; snapshots use mapped bytes, blocks, permissions, symbols, types, references, entry points, and canonical reports."
- **Scope of Review**:
  1. **Measure and Review `io.github.rezabakhshi.embedra.core.*` Coverage**:
     - Verify every single class in `io.github.rezabakhshi.embedra.core.*` meets or exceeds $\ge 90\%$ branch coverage.
     - Analyze any remaining unreached branches across core classes:
       - `io.github.rezabakhshi.embedra.core.budget.*` (`SharedResourceBudget`, `AdversarialArchiveGuard`, `AdversarialPathGuard`, `AdversarialXmlGuard`, `AdversarialRegexGuard`)
       - `io.github.rezabakhshi.embedra.core.stm32.input.*` (`Stm32VectorDiscovery`, `Stm32DfuParser`, `Stm32RawBinPlan`, `Stm32RawBinCandidate`)
       - `io.github.rezabakhshi.embedra.core.evidence.*` (`EvidenceIndex`, `EvidenceIndexEntry`)
       - `io.github.rezabakhshi.embedra.core.fixture.*` (`DeterministicGenerationRunner`, `PrivateFixtureManager`)
       - `io.github.rezabakhshi.embedra.core.model.*`, `io.github.rezabakhshi.embedra.core.io.*`, `io.github.rezabakhshi.embedra.core.diagnostic.*`
  2. **Audit and Formulate Exclusion / Enforcement Criteria**:
     - Ensure all exclusions (such as Ghidra GUI/adapter classes in `io.github.rezabakhshi.embedra.ghidra.*` requiring headless integration test environments or pure UI display) are explicitly justified and formally documented.
     - Review secondary core / parser / format packages:
       - `io.github.rezabakhshi.embedra.formats.esp.*`
       - `io.github.rezabakhshi.embedra.formats.esp8266.*`
       - `io.github.rezabakhshi.embedra.formats.rp.uf2.*`
       - `io.github.rezabakhshi.embedra.pack.*`
       - `io.github.rezabakhshi.embedra.svd.*`
     - Where branch or instruction gaps exist in critical parsing logic, author targeted unit/pure tests to eliminate unexercised branches, unreachable guards, or edge cases without weakening thresholds.
  3. **Produce Machine-Readable & Human-Readable Coverage Review Report**:
     - Publish a comprehensive core coverage review report in `.embedra/evidence/tasks/T070.md` detailing:
       - Exact per-package and per-class instruction and branch coverage metrics.
       - Mathematical breakdown of covered vs missed branches.
       - Detailed audit of reviewed exclusions (e.g., Ghidra adapter boundaries, GUI docking actions, Swing table models).
       - Status of JaCoCo enforcement rule in `gradle/build-quality.gradle`.

---

## 2. Verification Commands to Pass

Run and confirm 100% clean passes:

1. **Checkstyle verification**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon checkstyleMain checkstyleTest checkstyleIntegrationTest
   ```

2. **Core branch coverage verification**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon test jacocoTestReport jacocoTestCoverageVerification
   ```

3. **Pure tests & integration test suite**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon check pureTest
   ```

4. **Reproducible packaging verification**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC bash scripts/verify-build-quality.sh
   ```

5. **Continuity & provenance audit**:
   ```bash
   sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh
   ```

---

## 3. Continuity Update Protocol

Upon completing verification:
1. Mark `T070` as completed in `Embedra-SpecKit.md` (`- [x] T070`).
2. Record evidence in `.embedra/evidence/tasks/T070.md` with complete coverage tables, branch ratios, and exclusion audit.
3. Update `.embedra/evidence/evidence-index.json` with requirement-to-evidence links for T070.
4. Update `.embedra/state.json`:
   - Compute and update `.specification.sha256`.
   - Set `.currentTask.id` to `"T070"` with status `"COMPLETE"`.
   - Append `"T070"` to `completedTasks`.
   - Set `.evidence.task` to `".embedra/evidence/tasks/T070.md"`.
   - Set `nextTask` to `"T071"` and `nextAction` to `"Begin T071: run at least 10,000 deterministic malformed inputs per implemented binary format."`.
   - Append reproducible artifact entry to `.artifacts`.
5. Update `PROJECT_STATE.md` with current and completed task status.
