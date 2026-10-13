# T074 Handoff Command — Verify Discovery Completeness, Drift Detection, and Execution Topology

Work in `/home/rez0x61/Projects/ghidra_extension`. Implement **only T074** from `Embedra-SpecKit.md`:

> T074 Verify ESP and Raspberry Pi discovery completeness/drift, and verify exact support state and execution topology for every selected STM32 catalog part; STM32 additions require explicit review rather than silent expansion.

Do **not** begin T075. Do not commit, push, or publish unless explicitly asked.

---

## 0. Baseline to verify first (stop and report on any mismatch)

1. **Working Tree & Continuity**:
   - Working branch: `main`.
   - Working tree clean: `git status --short --branch`.
   - `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
   - `sha256sum Embedra-SpecKit.md` equals `.specification.sha256` in `.embedra/state.json` (`00f688d99ee766bf600dc6cf0e85bb9c9abf2b2360ff05388b8010fd74c609b2`).
   - `state.currentTask.id` is `T073` (`COMPLETE`), and `state.nextTask` is `T074`.
   - In `Embedra-SpecKit.md`: checkboxes T001 through T073 are checked (`- [x]`), and T074 is unchecked (`- [ ] T074`).

2. **Toolchain & Pinned Environment**:
   - Java 21 baseline: `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64`.
   - Ghidra 12.1.3 PUBLIC baseline: `GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`.
   - Gradle wrapper: `./gradlew --offline --no-daemon`.

3. **Read in order**:
   - `.embedra/state.json` and `.embedra/evidence/tasks/T073.md`.
   - `Embedra-SpecKit.md` (T074 release gate, Section 8 "Catalog and Discovery Invariants", Section 8.1 "ESP Family", Section 8.2 "Raspberry Pi Family", Section 8.3 "STM32 Family", and Section 10 "Testing Strategy: Vendor-catalog ingestion, schema, exact-part completeness, lifecycle/support-state, topology, and drift tests").
   - Existing catalog validation scripts and suites:
     - `catalogs/espressif/2026-09-23/catalog.json`
     - `catalogs/rp/2026-10-02/catalog.json`
     - `catalogs/stm32/2026-09-29/selection.json` and `catalogs/stm32/2026-09-29/curated-catalog.json`
     - `src/test/java/io/github/rezabakhshi/embedra/targets/esp/catalog/EspDeviceCatalogTest.java`
     - `src/test/java/io/github/rezabakhshi/embedra/targets/rp/catalog/RpDeviceCatalogTest.java`
     - `scripts/check-stm32-curated-selection-drift.py`
     - `scripts/check-stm32-market-drift.py`
     - `scripts/validate-stm32-fixture-catalog.py`
     - `scripts/tests/test_check_stm32_curated_selection_drift.py`
     - `scripts/tests/test_check_stm32_market_drift.py`
     - `scripts/tests/test_validate_stm32_fixture_catalog.py`

---

## 1. Scope and Core Requirements for T074

Per `Embedra-SpecKit.md`:
- **Core Requirement Contract**:
  - "Vendor-catalog ingestion, schema, exact-part completeness, lifecycle/support-state, topology, and drift tests."
  - "STM32 coverage is a curated, explicit allowlist of exact orderable parts, checked for catalog drift. The machine-readable acceptance list is `catalogs/stm32/2026-09-29/selection.json`; its 53 identities and 20 family labels are reviewed in T032 evidence... Further parts require a reviewed source, availability/common-use rationale, and a spec amendment. The UI must never present 'STM32 detected' as an exact part number when only a Cortex-M vector table was found."
  - "Every selected exact identity must be validated without expanding family names or wildcard references."
  - "STM32 additions require explicit review rather than silent expansion."
  - "Verify exact support state and execution topology for every selected STM32 catalog part."
  - "Verify ESP and Raspberry Pi discovery completeness/drift."

- **Scope of Implementation & Verification**:
  1. **ESP Family Catalog Discovery & Drift Verification**:
     - Verify catalog ingestion completeness: 53 silicon variants, 161 module profiles, 58 board profiles in `catalogs/espressif/2026-09-23/catalog.json`.
     - Ingestion of all 14 official series: `ESP32`, `ESP32-S2`, `ESP32-S3`, `ESP32-S31`, `ESP32-P4`, `ESP32-C2`, `ESP32-C3`, `ESP32-C5`, `ESP32-C6`, `ESP32-C61`, `ESP32-E22`, `ESP32-H2`, `ESP32-H21`, `ESP32-H4`.
     - Verify drift detection and provenance: SHA-256 digests of `source-facts.json` and `catalog.json` match `state.json`.
     - Verify support states: No unearned support state promotions; catalog-only parts remain `PLANNED`; ESP32-S3 application remains `EXPERIMENTAL`.
     - Verify execution topology: Xtensa dual-core (ESP32, ESP32-S3, ESP32-S31), Xtensa single-core (ESP32-S2), RISC-V single-core (C2, C3, C5, C6, C61, H2, H21, H4, E22), and RISC-V dual-core (P4).

  2. **Raspberry Pi Family Catalog Discovery & Drift Verification**:
     - Verify catalog completeness: All 5 silicon records (`RP2040`, `RP2350A`, `RP2350B`, `RP2354A`, `RP2354B`) and 4 board profiles (`Pico`, `Pico W`, `Pico 2`, `Pico 2 W`) in `catalogs/rp/2026-10-02/`.
     - Verify drift detection: Python tests (`test_generate_rp_catalog.py`, `test_generate_rp_fixtures.py`) and Java suite (`RpDeviceCatalogTest`).
     - Verify non-promotion: All silicon and board profiles remain `PLANNED` per RP-002.
     - Verify execution topology: RP2040 dual Cortex-M0+, RP2350/RP2354 dual Cortex-M33 (ARM) and dual Hazard3 (RISC-V), PIO coprocessor state machines, shared SRAM, and Boot2 XIP memory bounds.

  3. **STM32 Catalog: Exact Support State & Execution Topology Verification**:
     - Exact allowlist verification: Validate all 53 exact parts across 20 subfamilies against `catalogs/stm32/2026-09-29/selection.json`.
     - Anti-drift & Anti-silent-expansion: Verify that wildcards (`STM32F103*`) and family labels are rejected; only exact orderable part numbers resolve.
     - Execution topology for all 53 parts:
       - Single-core ARM Cortex-M0+ (STM32C0, G0, U0, WL)
       - Single-core ARM Cortex-M3 (STM32F1, F2)
       - Single-core ARM Cortex-M4 (STM32F4, G4, L4, L4+)
       - Single-core ARM Cortex-M7 (STM32F7, H7 single-core)
       - Dual-core heterogeneous ARM Cortex-M7 + Cortex-M4 (STM32H7 dual-core)
       - ARM Cortex-M33 with TrustZone (STM32L5, U5, H5, WBA)
       - ARM Cortex-M55 with NPU (STM32N6)
       - Wireless coprocessor companion topology (STM32WB, STM32WL)
       - Microprocessor multi-stage boot & application topology (STM32MP1, STM32MP2)
     - Memory layouts, interrupt vectors, and SVD applicability maps for every selected part.
     - Support states: All 53 parts have strictly recorded support states per feature (raw BIN, Intel HEX, ELF, vector table, SVD, TrustZone, dual-core, external memory).

---

## 2. Verification Protocol

1. **Checkstyle**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon checkstyleMain checkstyleTest checkstyleIntegrationTest
   ```
2. **Catalog and Drift Verification Suites**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon test --tests "*Catalog*" --tests "*Topology*"
   ```
3. **Full Gradle Check and Pure Tests**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon check pureTest
   ```
4. **Reproducible Packaging**:
   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=/home/rez0x61/Projects/ghidra_extension/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC bash scripts/verify-build-quality.sh
   ```
5. **Continuity Protocol**:
   - Update `Embedra-SpecKit.md`: check `- [x] T074`.
   - Author `.embedra/evidence/tasks/T074.md`.
   - Update `.embedra/evidence/evidence-index.json`.
   - Record commands in `.embedra/evidence/commands.jsonl`.
   - Update `.embedra/state.json`: currentTask T074 COMPLETE, completedTasks, nextTask T075.
   - Update `PROJECT_STATE.md`.
   - Confirm `sh scripts/validate-handoff.sh && sh scripts/validate-fixture-provenance.sh` pass.
