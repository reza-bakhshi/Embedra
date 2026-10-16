# Atmel / Microchip Family Acceptance Gate Report

## Result

`PASS`

Date: 2026-10-16. Maintainer approval: `APPROVED`.

This immutable gate report records the acceptance verification of the Atmel / Microchip family
workstream (T104–T111) as specified in `Embedra-SpecKit.md` Section 12 ("Atmel / Microchip family (T104-T111)").

## 1. Completed Tasks Covered

- **T104**: Audit and catalog specification for Atmel/Microchip across 8-bit AVR (ATmega, ATtiny, AVR-Dx)
  and 32-bit SAM (SAMD, SAME, SAMS, SAMV, SAML, SAMC, SAM3) against pinned Microchip Device Family Packs (DFP),
  ATDF schemas, datasheets, and license terms (`docs/atmel-audit.md`, `catalogs/atmel/2026-10-14/catalog.json`,
  `.embedra/evidence/tasks/T104-atmel-capability-matrix.json`).
- **T105**: Independently generated, redistributable Atmel/Microchip fixtures and official-tool oracles
  (Intel HEX, ELF, raw BIN) across representative ATmega328P, ATmega2560, ATtiny85, SAMD21G18A, and SAME70Q21
  parts, plus malformed, truncated, wrong-checksum, overlapping, and invalid-vector fixtures (`scripts/generate-atmel-fixtures.py`).
- **T106**: Pure Atmel/Microchip target providers, exact-part catalog registry, and memory planners
  (Flash `code`, SRAM `data`, EEPROM `eeprom`, I/O registers `io`, Fuse/Lock bytes, and SAM 32-bit linear memory)
  under shared `ParserLimits` and `CancellationToken` (`AtmelTargetProvider`, `AtmelCatalogRegistry`, `AtmelMemoryPlanner`).
- **T107**: AVR interrupt vector table parsing, scoring, entry-point resolution, and handler label generation
  for `RJMP` (2-byte) and `JMP` (4-byte) vector tables at 0x0000 and `BOOTSZ` bootloader addresses, plus
  Cortex-M vector tables for SAM parts (`AvrVectorTableParser`, `AtmelVectorTableScorer`, `AvrVectorEntryMatcher`).
- **T108**: Atmel/Microchip ATDF / SVD peripheral register data packs, I/O port bitfield definitions, fuse bit maps,
  and schema transforms from redistributable Microchip DFP device definitions (`AtmelPeripheralPack`,
  `catalogs/atmel/packs/`).
- **T109**: Real-Ghidra GUI and headless multi-program import for Intel HEX, ELF, and raw BIN, validating
  Ghidra `avr8:LE:16:default` (and variants) and ARM Cortex-M language bindings, multi-address-space mapping,
  transactional rollback, user artifact preservation, and headless parity (`AtmelFirmwareLoader`,
  `AtmelFirmwareMapper`, `AtmelFirmwareImportService`).
- **T110**: AVR and SAM common runtime signatures (Arduino core libraries, AVR-libc, Atmel START / ASF, FreeRTOS)
  and CTF/string/lead enrichment using shared analyzers (`AtmelSignaturePack`, `AtmelSignatureMatcher`,
  `AtmelCtfEnrichmentAnalyzer`, `EmbedraAtmelSignatureAnalyzer`).
- **T111**: Final acceptance gate review, test coverage verification, support matrix documentation, and
  promotion of the 5 verified representative parts to `SUPPORTED` while leaving all other parts `PLANNED`.

## 2. Pinned Specifications and Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`
- Ghidra: `12.1.3 PUBLIC`, build date `2026-08-17`
- Toolchain: OpenJDK `21.0.12` 64-bit; Gradle wrapper `9.6.1`
- Catalog snapshot: `catalogs/atmel/2026-10-14/catalog.json` (SHA-256 `049a9b6debc502998735913c01baa1dd61f8cd7e12730bbac4140d55a1e934a9`)
- Peripheral packs:
  - `catalogs/atmel/packs/atmega-peripherals.json`
  - `catalogs/atmel/packs/attiny-peripherals.json`
  - `catalogs/atmel/packs/avr-dx-peripherals.json`
  - `catalogs/atmel/packs/samd-peripherals.json`
  - `catalogs/atmel/packs/same-peripherals.json`

## 3. Verified Compatibility Claims

1. **Curated Atmel / Microchip Catalog Snapshot & Memory Architecture**:
   - Complete snapshot of 27 curated parts across 5 series: 7 ATmega, 6 ATtiny, 5 AVR-Dx, 5 SAMD, 4 SAME.
   - Pinned physical memory invariants verified:
     - Classic AVR Harvard address spaces: Flash code at `0x00000000`, SRAM data starting at `0x00000100` / `0x00000060` (after 32 registers + I/O memory), EEPROM separate space at `0x00000000`, separate `io` and `fuses` spaces.
     - Modern AVR-Dx Unified Data Space: Code Flash mapped into data space via 32 KB window at `0x8000`, SRAM at `0x4000`, I/O at `0x0000`–`0x0FFF`.
     - SAM 32-bit linear address space: Code Flash at `0x00000000` (SAMD) or `0x00400000` (SAME70), SRAM at `0x20000000` / `0x20400000`, peripherals at `0x40000000`.
     - Vector tables: 2-byte RJMP for <=8 KB Flash AVR (ATtiny85), 4-byte JMP for >8 KB Flash AVR (ATmega328P, ATmega2560), 4-byte vectors for Cortex-M SAM.
   - Zero architectural contamination between 8-bit AVR and 32-bit ARM Cortex-M.

2. **Verified Representative Parts (Promoted to `SUPPORTED`)**:
   - `ATmega328P` (ATmega Series, AVR RISC, 32 KiB Flash, 2 KiB RAM, 1 KiB EEPROM, Optiboot 0x7E00)
   - `ATmega2560` (ATmega Series, AVR RISC, 256 KiB Flash, 8 KiB RAM, 4 KiB EEPROM, >64KB RAMPZ)
   - `ATtiny85` (ATtiny Series, AVR RISC, 8 KiB Flash, 512 B RAM, 512 B EEPROM, 2-byte RJMP vectors)
   - `SAMD21G18A` (SAMD Series, ARM Cortex-M0+, 256 KiB Flash, 32 KiB RAM, USB, SAM-BA bootloader)
   - `SAME70Q21` (SAME Series, ARM Cortex-M7, 2048 KiB Flash, 384 KiB RAM, FPU, Ethernet, TCM)
   - All 22 other cataloged parts remain strictly `PLANNED` per ATMEL-010.

3. **Ghidra Integration & Parity**:
   - Multi-format input decoding (Intel HEX, ELF, raw BIN) with checksum and segment validation.
   - Harvard multi-address-space mapping linking Ghidra `code`, `data`, `eeprom`, `io`, and `fuses` spaces.
   - AVR vector table discovery and handler labeling at reset (`0x0000`) and bootloader (`BOOTSZ`) addresses.
   - Transactional rollback on failure via `GhidraProgramTransaction`.
   - Headless and GUI import equivalence verified via `GhidraProgramEquivalenceAssertor`.

4. **Signatures & Enrichment**:
   - Arduino Core (AVR8): `init`, `pinMode`, `digitalWrite`, `digitalRead`, `delay`, `millis`, `HardwareSerial::begin`.
   - AVR-libc (AVR8): `__do_copy_data`, `__do_clear_bss`, `malloc`, `free`, `__bad_interrupt`.
   - Atmel START / ASF (SAM Cortex-M): `system_init`, `delay_ms`, `usart_sync_enable`, `gpio_set_pin_level`.
   - FreeRTOS (SAM & AVR8): `vTaskStartScheduler`, `xTaskCreate`, `vTaskDelay`, `xQueueGenericCreate`.
   - 16-bit and 32-bit pointer-aware CTF entity recovery (flags, URLs, credentials, command tables) and security lead discovery.

## 4. Verification Sign-Off

- `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=$PWD/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon checkstyleMain checkstyleTest checkstyleIntegrationTest test ghidraIntegrationTest pureTest`: `BUILD SUCCESSFUL` (1144 Java tests passing, 0 failures, 0 errors).
- `python3 -m unittest discover -s scripts/tests`: `233 tests passed (0 failures)`.
- `sh scripts/validate-handoff.sh`: `0 errors`.
- `sh scripts/validate-fixture-provenance.sh`: `0 errors`.
