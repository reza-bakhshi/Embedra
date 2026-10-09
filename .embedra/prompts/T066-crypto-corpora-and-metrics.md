# T066 Handoff Command — Positive/Negative Crypto Corpora, Per-Detector Metrics, Precision, Recall, and Unsupported Cases

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T066** from `Embedra-SpecKit.md`:

> T066 Build positive/negative crypto corpora across ESP, STM32, RP2040, and RP2350-family ISAs/toolchains; measure and publish per-detector precision, recall, false-positive rate, confidence thresholds, and unsupported cases.

Do **not** begin T067. Do not commit, push, or publish unless explicitly asked.

---

## 0. Baseline to verify first (stop and report on any mismatch)

1. **Working Tree & Continuity**:
   - Working branch: `main`.
   - `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
   - `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in `.embedra/state.json` (`5b6b62ac31b7b34d642857064734e9a716eb372924a4c7cdd24bec5c6cb1ffd2`).
   - `state.currentTask.id` is `T065` (`COMPLETE`), and `state.nextTask` is `T066`.
   - In `Embedra-SpecKit.md`: checkboxes T001 through T065 are checked (`[x]`), and T066 is unchecked (`- [ ] T066`).

2. **Toolchain & Pinned Environment**:
   - Java 21 baseline: `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64`.
   - Ghidra 12.1.3 PUBLIC baseline: `GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`.
   - Build quality gate: `./gradlew -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR check pureTest` and `bash scripts/verify-build-quality.sh`.

3. **Read in order**:
   - `.embedra/state.json` and `.embedra/evidence/tasks/T065.md`.
   - `Embedra-SpecKit.md` (T066 scope, AN-010, AN-011, AN-012, AN-013, AN-014, AN-015, AN-003, AN-008).
   - `PROJECT_STATE.md` and `docs/architecture.md`.
   - Existing crypto subsystems:
     - `io.github.rezabakhshi.embedra.analyzers.crypto.tables.*` (`CryptoTableDatabase`, `CryptoTableSignature`)
     - `io.github.rezabakhshi.embedra.analyzers.crypto.entropy.*` (`EntropyScanner`, `LikelyKeyScanner`)
     - `io.github.rezabakhshi.embedra.analyzers.crypto.signatures.*` (`CryptoLibrarySignatureMatcher`, `CryptoSignatureDatabase`, `CryptoSignaturePackLoader`)
     - `io.github.rezabakhshi.embedra.analyzers.crypto.hardware.*` (`HardwareCryptoAnalyzer`, `HardwareCryptoCatalog`, `HardwareCryptoPlatform`)
     - `io.github.rezabakhshi.embedra.analyzers.crypto.fusion.*` (`CryptoAnalysisPipeline`, `CryptoAnalysisReport`)
     - `io.github.rezabakhshi.embedra.ghidra.crypto.*` (`EmbedraCryptoAnalyzer`, `GhidraCryptoApplicator`)

---

## 1. Scope and Core Requirements for T066

Per **AN-015**, **AN-014**, **AN-013**, and **AN-012**:

1. **Positive/Negative Crypto Corpora**:
   - Build dedicated, deterministic positive corpora containing known cryptographic implementations, hardware engine use, ROM calls, constant tables, candidate keys, and certificates across:
     - **ESP family**: Xtensa (`ESP32`, `ESP32-S3`) and RISC-V 32 (`ESP32-C3`, `ESP32-C6`).
     - **STM32 family**: ARM Cortex-M Thumb (`STM32F4`, `STM32F7`, `STM32H7`, `STM32L4`, `STM32WB`).
     - **RP family**: ARM Cortex-M0+ (`RP2040`), ARM Cortex-M33 / RISC-V (`RP2350`).
   - Build adversarial negative corpora containing:
     - Non-crypto lookup tables (sine tables, CRC tables, encoding tables like Base64/Hex, Huffman frequency tables, character classification matrices).
     - Non-crypto high-entropy data (compressed audio/images, LZ4/Deflate compressed streams, pseudorandom textures).
     - Code idioms and jump tables that mimic constant sequences without cryptographic semantics.

2. **Per-Detector Benchmark & Metrics Engine**:
   - Create a pure, bounded evaluation engine (e.g. `CryptoCorpusBenchmark` / `CryptoEvaluationEngine` in `analyzers.crypto.corpus`):
     - Calculates True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN).
     - Computes per-detector and per-algorithm:
       - **Precision**: $TP / (TP + FP)$
       - **Recall**: $TP / (TP + FN)$
       - **False-Positive Rate (FPR)**: $FP / (FP + TN)$
       - **F1 Score**: $2 \cdot (\text{Precision} \cdot \text{Recall}) / (\text{Precision} + \text{Recall})$
     - Evaluates confidence calibration across `CONFIRMED`, `LIKELY`, `PLAUSIBLE`, `LEAD`.
     - Explicitly records **unsupported cases** and variants so "not found" is never confused with "not present".

3. **Metrics Publishing & Reporting**:
   - Generate structured evaluation reports:
     - Pure machine-readable JSON metrics export (`CryptoBenchmarkReport`).
     - Markdown evaluation matrix detailing detector performance, thresholds, and limitations.
     - Documented published metrics in `.embedra/evidence/tasks/T066.md` and `docs/support-matrix.md`.

---

## 2. Invariants & Architectural Rules

- **Pure / Adapter Separation**: All corpus evaluators, test fixtures, and benchmark calculators must live in pure modules without importing `ghidra.*` (verified by `ArchitectureBoundaryTest`).
- **Resource Limits & Cancellation**: Benchmark execution must respect `ParserLimits` and check `CancellationToken`.
- **Zero Secret Leaking**: Test reports and benchmark outputs must not print raw secrets in plain text (enforce `maskedValue()` / AN-008).
- **Strict Differentiation (AN-003)**: The benchmark must assert that negative non-crypto fixtures (Base64, Deflate, CRC tables, LZ4) never receive `isEncryption() == true`.

---

## 3. Verification Commands to Pass

```bash
# 1. Pure test suite (all unit and benchmark tests)
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew pureTest

# 2. Checkstyle verification
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew checkstyleMain checkstyleTest

# 3. Full project check (including Ghidra integration tests and JaCoCo coverage)
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew check

# 4. Bit-for-bit reproducible packaging
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC bash scripts/verify-build-quality.sh

# 5. Handoff and fixture provenance validation
sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh
```

---

## 4. Final Handoff Sequence for T066

1. Create `.embedra/evidence/tasks/T066.md` detailing corpus design, evaluated ISAs/toolchains, precision/recall metrics, and test outputs.
2. Mark checkbox `- [x] T066` in `Embedra-SpecKit.md`.
3. Compute new `sha256sum Embedra-SpecKit.md` and record in `.embedra/state.json`.
4. Update `.embedra/state.json` setting `currentTask` to `T066` (`COMPLETE`), append `T066` to `completedTasks`, set `nextTask` to `T067`, and update latest artifact SHA-256 and size.
5. Update `PROJECT_STATE.md` with T066 completion.
6. Run `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` to confirm zero drift.
