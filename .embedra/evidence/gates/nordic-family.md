# Nordic Semiconductor nRF Family Acceptance Gate Report

## Result

`PASS`

Date: 2026-10-14. Maintainer approval: `APPROVED`.

This immutable gate report records the acceptance verification of the Nordic Semiconductor nRF family
workstream (T096–T103) as specified in `Embedra-SpecKit.md` Section 12 ("Nordic Semiconductor nRF family (T096-T103)").

## 1. Completed Tasks Covered

- **T096**: Curated Nordic Semiconductor family catalog, memory architecture, SoftDevice/MBR boundaries,
  and dual-core/TrustZone audit across nRF51, nRF52, nRF53, nRF54, and nRF91 series
  (`docs/nordic-audit.md`, `.embedra/evidence/tasks/T096-nordic-capability-matrix.json`).
- **T097**: Independently generated, redistributable Nordic firmware fixture corpus (Intel HEX, ELF, raw BIN)
  and provenance manifests across representative parts (`scripts/generate-nordic-fixtures.py`).
- **T098**: Pure Nordic target providers, exact silicon part registry, and memory/peripheral planning models
  (`Nrf51TargetProvider` through `Nrf91TargetProvider`, `NordicCatalogRegistry`, `NordicMemoryPlanner`).
- **T099**: SoftDevice / MBR / Bootloader partition discovery, vector relocation, SoftDevice API table resolution
  (SVC handler dispatch), and dual-core firmware layout analysis (`NordicSoftDeviceDetector`, `NordicDualCoreAnalyzer`).
- **T100**: Nordic SVD / MDK peripheral register data packs, EasyDMA definitions, bitfield schemas, and CryptoCell
  CC310/CC312 hardware peripheral definitions across all 5 series (`catalogs/nordic/packs/`).
- **T101**: Real-Ghidra GUI and headless multi-program import (`NordicFirmwareLoader`, `NordicFirmwareMapper`,
  `NordicFirmwareImportService`), validating ARM Cortex-M bindings, composite SoftDevice + App layout resolution,
  dual-core nRF5340 IPC binding, TrustZone nRF9160 Secure/Non-Secure mapping, transactional rollback, and GUI/headless parity.
- **T102**: nRF5 SDK and nRF Connect SDK (Zephyr) crypto/networking signatures, BLE stack identifiers, and
  CTF/string/lead enrichment pipelines (`NordicSignaturePack`, `NordicSignatureMatcher`, `NordicCtfEnrichmentAnalyzer`,
  `EmbedraNordicSignatureAnalyzer`).
- **T103**: Final acceptance gate review, test coverage verification, support matrix documentation, and promotion
  of the 5 verified representative parts to `SUPPORTED` while leaving all other parts `PLANNED`.

## 2. Pinned Specifications and Environment

- Host: Linux x86-64, kernel `7.0.0-31-generic`
- Ghidra: `12.1.3 PUBLIC`, build date `2026-08-17`
- Toolchain: OpenJDK `21.0.12` 64-bit; Gradle wrapper `9.6.1`
- Catalog snapshot: `catalogs/nordic/2026-10-13/catalog.json` (SHA-256 `b95b84f1a476e7e2585b96b1981a185040fa761d021fdf751959e6abb618f5d9`)
- Peripheral packs:
  - `catalogs/nordic/packs/nrf51-peripherals.json`
  - `catalogs/nordic/packs/nrf52-peripherals.json`
  - `catalogs/nordic/packs/nrf53-peripherals.json`
  - `catalogs/nordic/packs/nrf54-peripherals.json`
  - `catalogs/nordic/packs/nrf91-peripherals.json`

## 3. Verified Compatibility Claims

1. **Curated Nordic Catalog Snapshot & Architecture**:
   - Complete snapshot of 21 curated parts across 5 series: 5 nRF51, 8 nRF52, 2 nRF53, 2 nRF54, 4 nRF91.
   - Pinned physical memory invariants verified:
     - Code Flash base: `0x00000000`
     - Internal SRAM base: `0x20000000`
     - Factory Information Configuration Registers (FICR): `0x10000000` (`0x00FF0000` on nRF53/nRF54)
     - User Information Configuration Registers (UICR): `0x10001000` (`0x00FF8000` on nRF53/nRF54)
     - Non-Secure APB MMIO aperture: `0x40000000`
     - Secure MMIO aperture: `0x50000000`
     - Hardware crypto: CryptoCell CC310 (`0x5002A000` on nRF52840) and CC312 (`0x50840000` on nRF5340 / nRF9160)
   - Zero architectural overlap or boundary violations.

2. **Verified Representative Parts (Promoted to `SUPPORTED`)**:
   - `nRF51822-QFAA` (nRF51 Series, ARM Cortex-M0, 256 KiB Flash, 16 KiB RAM)
   - `nRF52832-QFAA` (nRF52 Series, ARM Cortex-M4F, 512 KiB Flash, 64 KiB RAM)
   - `nRF52840-QIAA` (nRF52 Series, ARM Cortex-M4F, 1024 KiB Flash, 256 KiB RAM, CryptoCell CC310, USB)
   - `nRF5340-QKAA` (nRF53 Series, Dual ARM Cortex-M33, 1280 KiB Flash, 576 KiB RAM, TrustZone, CryptoCell CC312)
   - `nRF9160-SICA` (nRF91 Series, ARM Cortex-M33, 1024 KiB Flash, 256 KiB RAM, TrustZone LTE-M/NB-IoT, CryptoCell CC312)
   - All 16 other cataloged parts remain strictly `PLANNED` per NRF-010.

3. **Ghidra Integration & Parity**:
   - Multi-format input decoding (raw BIN, Intel HEX, ELF) with checksum and segment validation.
   - Multi-image layout resolution aligning MBR (`0x00000000`), SoftDevice (`0x00001000`), Application
     (`0x00019000` for S112, `0x00026000` for S132, `0x00027000` for S140), and bootloader from UICR `0x10001014`.
   - Dual-core nRF5340 cross-program binding linking Application core and Network core via shared IPC channels.
   - TrustZone Secure and Non-Secure program separation on nRF9160.
   - Transactional rollback on failure via `GhidraProgramTransaction`.
   - Headless and GUI import equivalence verified via `GhidraProgramEquivalenceAssertor`.

4. **Signatures & Enrichment**:
   - nRF5 SDK BLE routine signatures (`sd_ble_gap_adv_start`, `sd_ble_gatts_service_add`) and runtime drivers (`nrfx_gpiote_init`, `app_timer_create`, `nrf_crypto_init`).
   - nRF Connect SDK (Zephyr) signatures (`bt_enable`, `bt_le_adv_start`, `psa_crypto_init`, `z_cstart`).
   - 32-bit pointer-aware CTF entity recovery (flags, URLs, credentials) and security lead discovery.

## 4. Verification Sign-Off

- `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=$PWD/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC ./gradlew --offline --no-daemon checkstyleMain checkstyleTest checkstyleIntegrationTest test ghidraIntegrationTest pureTest`: `BUILD SUCCESSFUL`.
- `python3 -m unittest discover -s scripts/tests`: `216 tests passed (0 failures)`.
- `sh scripts/validate-handoff.sh`: `0 errors`.
- `sh scripts/validate-fixture-provenance.sh`: `0 errors`.
