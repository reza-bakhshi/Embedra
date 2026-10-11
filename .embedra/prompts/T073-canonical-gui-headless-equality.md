# T073 Handoff Command — Verify Canonical GUI/Headless Equality for Every Golden Fixture

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T073** from `Embedra-SpecKit.md`:

> T073 Verify canonical GUI/headless equality for every golden fixture.

Do **not** begin T074. Do not commit, push, or publish unless explicitly asked.

---

## 0. Baseline to verify first (stop and report on any mismatch)

1. **Working Tree & Continuity**:
   - Working branch: `main`.
   - `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
   - `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in `.embedra/state.json` (`657eb50848274aae53b298dd91780a170ee45ddcd96bedd8245df2b619fc4053`).
   - `state.currentTask.id` is `T072` (`COMPLETE`), and `state.nextTask` is `T073`.
   - In `Embedra-SpecKit.md`: checkboxes T001 through T072 are checked (`- [x]`), and T073 is unchecked (`- [ ] T073`).

2. **Toolchain & Pinned Environment**:
   - Java 21 baseline: `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64`.
   - Ghidra 12.1.3 PUBLIC baseline: `GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`.
   - Gradle wrapper: `./gradlew --offline --no-daemon`.

3. **Read in order**:
   - `.embedra/state.json` and `.embedra/evidence/tasks/T072.md`.
   - `Embedra-SpecKit.md` (T073 release gate, Sections 1.1, 9 "Headless", 10 "Testing Strategy: GUI-equivalent/headless snapshot equality", and 12.1).
   - Existing workflow equivalence suites:
     - `src/integrationTest/java/io/github/rezabakhshi/embedra/ghidra/esp/EspWorkflowEquivalenceTest.java`
     - `src/integrationTest/java/io/github/rezabakhshi/embedra/ghidra/rp/RpWorkflowEquivalenceTest.java`

---

## 1. Scope and Core Requirements for T073

Per `Embedra-SpecKit.md`:
- **Requirement Contract**:
  - "GUI-equivalent/headless snapshot equality."
  - "All user choices have explicit command options or configuration files. Missing decisions fail with structured diagnostics rather than interactive fallback. Canonical JSON is always available."
  - "Coverage percentage alone is never acceptance evidence. Decompiler text is not a stable oracle; snapshots use mapped bytes, blocks, permissions, symbols, types, references, entry points, and canonical reports."
  - Canonical reports exclude host paths and non-deterministic timestamps, guaranteeing bit-for-bit equivalence regardless of execution mode, interactive/headless runner, timezone, or locale.

- **Scope of Implementation & Verification**:
  1. **Comprehensive Golden Fixture Coverage Across All Implemented Families**:
     - **ESP32 Family**:
       - ESP32-S3 application image (`fixtures/esp32s3/esp32s3-freestanding-minimal.bin`).
       - ESP32-S3 full-flash multi-program workspace (`fixtures/esp32s3/full-flash/default-factory.bin`).
       - ESP32 original application (`fixtures/esp32/esp32-freestanding-minimal.bin`).
       - ESP32-S2 application (`fixtures/esp32s2/esp32s2-freestanding-minimal.bin`).
       - ESP32-C3 RISC-V application (`fixtures/esp32c3/esp32c3-freestanding-minimal.bin`).
       - Other supported ESP family variants (`esp32c2`, `esp32c5`, `esp32c6`, `esp32c61`, `esp32h2`, `esp32h21`, `esp32h4`, `esp32p4`, `esp32s31`, `esp32e22`).
     - **ESP8266 Family**:
       - Legacy v1 images (`fixtures/esp8266/esp8266-freestanding-v1-0x00000.bin`, `0x01010.bin`).
       - Legacy v2 image (`fixtures/esp8266/esp8266-freestanding-v2-0x01000.bin`).
     - **Raspberry Pi Family**:
       - RP2040 UF2 (`fixtures/rp/rp2040-pico-blinky.uf2`).
       - RP2040 dual-core ELF (`fixtures/rp/rp2040-freestanding-dualcore.elf`).
       - RP2040 Boot2 XIP binary (`fixtures/rp/rp2040-boot2-xip.bin`).
       - RP2350 ARM Cortex-M33 UF2 (`fixtures/rp/rp2350-arm-pico2.uf2`).
       - RP2350 Hazard3 RISC-V UF2 (`fixtures/rp/rp2350-riscv-pico2.uf2`).
       - RP2350 TrustZone & Trap ELFs (`fixtures/rp/rp2350-arm-trustzone.elf`, `fixtures/rp/rp2350-riscv-trap.elf`).
       - RP2354 stacked-flash binary (`fixtures/rp/rp2354-stacked-flash.bin`).
     - **STM32 Family**:
       - Representative STM32 core samples across formats (BIN, HEX, ELF) and silicon families:
         - Cortex-M0/M0+: `STM32C0` (`STM32C051C8T6`, `STM32C071RBT6`, `STM32C092RCT6`), `STM32G0B1RET6`, `STM32U031R8T6`.
         - Cortex-M3: `STM32F103` (`STM32F103C8T6`, `STM32F103CBT6`, `STM32F103RBT6`), `STM32F207ZGT6`.
         - Cortex-M4: `STM32F401RET6`, `STM32G431RBT6`, `STM32L412KBU3`, `STM32L4P5CGU6`, `STM32WB15CCU6`, `STM32WL33CCV6TR`.
         - Cortex-M7: `STM32F756ZGT6`, `STM32H735IGK6`.
         - Cortex-M33 (TrustZone): `STM32H503RBT6`, `STM32L562QEI6Q`, `STM32U545RET6Q`, `STM32WBA25CEU7`.
         - Cortex-M55 / N6: `STM32N657X0H3Q`.
         - STM32MP MPU / Heterogeneous: `fixtures/stm32mp/stm32mp157c-minimal.dts`.
  2. **Canonical Snapshot & Equality Invariants**:
     - Program memory blocks: count, names, start/end bounds, permissions (R/W/X/Volatile), byte initialization, and identical SHA-256 byte contents.
     - Symbol table: symbol names, namespaces, addresses, symbol types, and pinned primary symbols.
     - Entry points: external entry point set equality.
     - Bookmarks & options: category, comment, and property map equality.
     - Canonical report JSON equality: bit-for-bit string equality of `canonicalReportJson()` across independent imports performed under divergent environments (e.g. locale `tr-TR` vs `ja-JP`, timezone `Asia/Tehran` vs `Pacific/Auckland` vs `UTC`).
  3. **Integration Test Suite**:
     - Author or expand integration tests in `src/integrationTest/java/io/github/rezabakhshi/embedra/ghidra/` to systematically assert GUI/headless equality across all golden fixture classes.
  4. **Machine-Readable & Human-Readable Evidence**:
     - Publish `.embedra/evidence/tasks/T073.md` detailing every tested golden fixture, input format, target device, and the exact equality assertions verified.

---

## 2. Verification Commands to Pass

Run and confirm 100% clean passes:

1. **Checkstyle verification**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon checkstyleMain checkstyleTest checkstyleIntegrationTest
   ```

2. **Ghidra GUI/Headless equality integration test suite**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon ghidraIntegrationTest
   ```

3. **Core branch coverage verification**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon test jacocoTestReport jacocoTestCoverageVerification
   ```

4. **Pure tests & full check**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon check pureTest
   ```

5. **Reproducible packaging verification**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC bash scripts/verify-build-quality.sh
   ```

6. **Continuity & provenance audit**:
   ```bash
   sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh
   ```

---

## 3. Continuity Update Protocol

Upon completing verification:
1. Mark `T073` as completed in `Embedra-SpecKit.md` (`- [x] T073`).
2. Record evidence in `.embedra/evidence/tasks/T073.md` with complete matrix of golden fixtures, verified canonical snapshots, and byte/symbol equivalence results.
3. Update `.embedra/evidence/evidence-index.json` with requirement-to-evidence links for T073.
4. Update `.embedra/state.json`:
   - Compute and update `.specification.sha256`.
   - Set `.currentTask.id` to `"T073"` with status `"COMPLETE"`.
   - Append `"T073"` to `completedTasks`.
   - Set `.evidence.task` to `".embedra/evidence/tasks/T073.md"`.
   - Set `nextTask` to `"T074"` and `nextAction` to `"Begin T074: verify ESP and Raspberry Pi discovery completeness/drift, and verify exact support state and execution topology for every selected STM32 catalog part."`.
   - Append reproducible artifact entry to `.artifacts`.
5. Update `PROJECT_STATE.md` with current and completed task status.
