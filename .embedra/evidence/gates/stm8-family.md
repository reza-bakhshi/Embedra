# STM8 8-bit MCU Family Acceptance Gate Report

## Result

`PASS`

Date: 2026-10-13. Maintainer approval: `APPROVED`.

This immutable gate report records the acceptance verification of the STM8 8-bit microcontroller family
workstream (T088–T095) as specified in `Embedra-SpecKit.md` Section 12 ("STM8 8-bit MCU family (T088-T095)").

## 1. Completed Tasks Covered

- **T088**: Curated STM8 family catalog, memory architecture, peripheral register, and toolchain audit across
  STM8S, STM8L, STM8A, and STM8T (`docs/stm8-audit.md`, `.embedra/evidence/tasks/T088-stm8-capability-matrix.json`).
  Enforced strict architectural segregation from 32-bit Cortex-M STM32.
- **T089**: Independently generated, redistributable STM8 firmware fixture corpus, reference compiler oracles
  (SDCC, Cosmic), and provenance manifests across all 8 representative parts (`scripts/generate-stm8-fixtures.py`).
- **T090**: STM8 target provider, exact silicon part registry, and memory/peripheral planning models
  (`Stm8TargetProvider`, `Stm8CatalogRegistry`, `Stm8MemoryPlanner`).
- **T091**: Multi-format input decoding supporting Intel HEX, Motorola S-Record, ELF, and raw BIN vector inference
  anchored at `0x008000`.
- **T092**: STM8 peripheral definitions, register windows, and interrupt vector mapping for STM8S, STM8L, STM8A
  (`catalogs/stm8/packs/`).
- **T093**: Real-Ghidra GUI and headless multi-program import (`Stm8FirmwareLoader`, `Stm8FirmwareMapper`),
  validating 8-bit SLEIGH language binding, transactional rollback, user option preservation, and headless equality.
- **T094**: Standard Peripheral Library (SPL) and open-source compiler runtime (SDCC, Cosmic) signatures, as well as
  CTF entity recovery and security lead enrichment pipelines.
- **T095**: Final acceptance gate review, test coverage verification, support matrix documentation, and promotion
  of the 8 verified representative parts to `SUPPORTED` while leaving all other parts `PLANNED`.

## 2. Pinned Specifications and Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`
- Ghidra: `12.1.3 PUBLIC`, build date `2026-08-17`
- Toolchain: OpenJDK `21.0.12` 64-bit; Gradle wrapper `9.6.1`
- Reference firmware toolchains: SDCC v4.2.0; Cosmic STM8 C compiler v4.4.11
- Catalog snapshot: `catalogs/stm8/2026-10-13/catalog.json` (SHA-256 `a29012b1c9e39c25109c10fb097b0a25225ec416fe9fe43c86a65a0a1270bbb7`)
- Peripheral packs:
  - `catalogs/stm8/packs/stm8s-peripherals.json`
  - `catalogs/stm8/packs/stm8l-peripherals.json`
  - `catalogs/stm8/packs/stm8a-peripherals.json`

## 3. Verified Compatibility Claims

1. **Curated STM8 Catalog Snapshot & Architecture**:
   - Complete snapshot of 32 curated parts across 4 families: 14 STM8S, 8 STM8L, 7 STM8A, 3 STM8T.
   - Pinned physical memory invariants verified:
     - RAM base: `0x000000`
     - EEPROM base: `0x004000`
     - Option bytes base: `0x004800`
     - Peripheral registers base: `0x005000` to `0x0057FF`
     - Boot ROM base: `0x006000` to `0x0067FF`
     - Flash program memory base: `0x008000`
     - Vector table base: `0x008000` (32 slots, 4 bytes each, opcode `0x82` / JPF)
   - Zero Cortex-M or 32-bit architectural contamination.

2. **Verified Representative Parts (Promoted to `SUPPORTED`)**:
   - `STM8S003F3P6` (STM8S Value line, 8 KiB Flash, 1 KiB RAM, 128 B EEPROM)
   - `STM8S103F3P6` (STM8S Access line, 8 KiB Flash, 1 KiB RAM, 640 B EEPROM)
   - `STM8S208RBT6` (STM8S Performance line with CAN, 128 KiB Flash, 6 KiB RAM, 2 KiB EEPROM)
   - `STM8L151C8T6` (STM8L Low power line, 64 KiB Flash, 4 KiB RAM, 2 KiB EEPROM)
   - `STM8L152R8T6` (STM8L Ultra-low-power line with LCD, 64 KiB Flash, 4 KiB RAM, 2 KiB EEPROM)
   - `STM8AF5288TAY` (STM8AF Automotive line with CAN, 64 KiB Flash, 6 KiB RAM, 2 KiB EEPROM)
   - `STM8AL3188TA` (STM8AL Automotive low-power line, 64 KiB Flash, 4 KiB RAM, 2 KiB EEPROM)
   - `STM8T143AU` (STM8T Touch-sensing line, 8 KiB Flash, 1 KiB RAM, 128 B EEPROM)
   - All 24 other parts remain strictly `PLANNED` or `UNSUPPORTED`.

3. **Ghidra Integration & Parity**:
   - Multi-format input decoding (raw BIN, Intel HEX, Motorola S-Record, ELF) with checksum validation.
   - Transactional rollback on failure via `GhidraProgramTransaction`.
   - Persistence of user options under `Embedra STM8 Options`.
   - Headless and GUI import equivalence verified.

4. **Signatures & Enrichment**:
   - STM8 SPL routine signatures (`GPIO_Init`, `CLK_DeInit`, `UART1_Init`, `TIM1_Cmd`, `SPI_Init`).
   - Compiler runtime signatures for SDCC (`__divsint`, `__mullong`, `__mulint`) and Cosmic (`_switch`, `_i_div`, `_l_mul`).
   - 8-bit / 16-bit / 24-bit pointer-aware CTF entity recovery and security lead discovery.

## 4. Verification Sign-Off

- `./gradlew --offline --no-daemon checkstyleMain checkstyleTest pureTest`: `BUILD SUCCESSFUL`.
- `sh scripts/validate-handoff.sh`: `0 errors`.
- `sh scripts/validate-fixture-provenance.sh`: `0 errors`.
- `python3 -m unittest discover scripts/tests/`: `197 tests passed (0 failures)`.
