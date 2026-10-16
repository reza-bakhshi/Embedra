# ESP32-Branded Full-Flash Layout & Architectural Audit

This document records the official technical audit and per-series capability
matrix for all 14 ESP32-branded microcontroller series cataloged in the Embedra
project (`catalogs/espressif/2026-09-23/catalog.json`), establishes the explicit
segregation of legacy ESP8266 devices, inventories current hardcoded ESP32-S3
assumptions across shared classes, and specifies the common layout provider
architecture planned for T082 in accordance with `Embedra-SpecKit.md` (US4A,
ESP-015 through ESP-027, Section 8.1, and Section 12).

## 1. Scope and Pinned Authoritative Baselines

The audit encompasses all 14 ESP32-branded series cataloged in Embedra's offline
Espressif catalog snapshot (`catalogs/espressif/2026-09-23/catalog.json`, 53
silicon parts, 161 module profiles, 58 board profiles):
1. `ESP32` (Original dual/single LX6)
2. `ESP32-S2` (Single LX7)
3. `ESP32-S3` (Dual LX7)
4. `ESP32-S31` (Dual RISC-V / NPU)
5. `ESP32-P4` (Dual RISC-V HP + LP)
6. `ESP32-C2` / `ESP8684` (Single RV32IMC)
7. `ESP32-C3` / `ESP8685` (Single RV32IMC)
8. `ESP32-C5` (Single RV32IMAC dual-band Wi-Fi 6)
9. `ESP32-C6` (Single RV32IMAC + LP RV32)
10. `ESP32-C61` (Single RV32IMAC)
11. `ESP32-E22` (Dual RV32 edge-AI)
12. `ESP32-H2` (Single RV32IMAC 802.15.4 / BLE)
13. `ESP32-H21` (Single RV32IMAC)
14. `ESP32-H4` (Dual RV32IMAC)

Authoritative specifications and pinned reference baselines:
- **ESP-IDF v6.0 reference tree**: git revision `662a3be354759d9487bf4b1a629fadb766cb1800`
  (components `soc`, `esp_rom`, `bootloader_support`, `partition_table`).
- **esptool v5.4.0 target definitions**: `esptool/targets/*.py`
  (defines chip ID constants, ROM loaders, flash parameters, and memory maps).
- **Espressif Technical Reference Manuals (TRMs) & Datasheets**:
  official vendor hardware architecture specifications for memory maps, cache MMU
  page tables, and ROM boot sequences.

## 2. Segregation of ESP8266 Legacy Format

ESP8266 is explicitly segregated from the ESP32-branded full-flash architecture
as mandated by ESP-020, ESP-022, and ADR 0025:

1. **Header Structure Incompatibility**:
   - ESP8266 firmware images predate the ESP32 extended image header format (`0xE9`
     v1 layout with 24-byte header containing chip ID at offset 12).
   - ESP8266 uses either legacy v1 (8-byte header: `0xE9`, segment count, SPI mode,
     SPI speed/size, entry point) or legacy v2 (starts with magic `0xEA`, embeds
     an IROM segment followed by a nested v1 RAM image, and ends with an SDK CRC).
   - ESP8266 image headers have **no chip ID field**, making chip-ID-based target
     identification structurally impossible from image bytes alone.

2. **Partition Table Absence**:
   - ESP8266 uses fixed non-partitioned flash layouts rather than the standard ESP
     partition table format (`0x50AA` magic entries with `0xEBEB` MD5 trailer).
   - Typical ESP8266 flash layouts place code and data at fixed hardcoded offsets:
     - Non-FOTA: `0x00000` (`eagle.flash.bin`) and `0x10000` or `0x40000` (`eagle.irom0text.bin`).
     - FOTA (v2): bootloader at `0x00000`, `user1.bin` at `0x01000`, `user2.bin` at
       `0x81000` (1 MiB) or `0x101000` (2 MiB+), and RF/system parameter sectors at
       the end of physical flash.
   - There is no MD5-verified partition table at `0x8000` or anywhere else in flash.

3. **Processor Architecture & Memory Organization**:
   - ESP8266 employs an Xtensa LX106 core (Harvard architecture, 32-bit instructions,
     16-bit registers) distinct from ESP32 LX6, LX7, or RISC-V cores.
   - Its flash mapping relies on 1 MiB mapping banks rather than the 64 KiB MMU pages
     used by modern ESP32 SoCs.

4. **Architectural Policy**:
   - Per ADR 0025 and ESP-020, ESP8266 remains isolated in its own dedicated package
     (`io.github.rezabakhshi/embedra.formats.esp8266` and
     `io.github.rezabakhshi/embedra.ghidra.esp8266`).
   - ESP8266 support MUST NEVER be counted as proof of ESP32 full-flash support,
     nor will ESP32 full-flash planners attempt to parse ESP8266 flash captures.

## 3. Per-Series Capability Matrix

The following capability matrix audits every cataloged ESP32-branded series against
pinned ESP-IDF v6.0 and esptool v5.4.0 specifications:

| Series | CPU Arch / Cores | Ghidra Language | Chip ID (Dec / Hex) | Bootloader Flash Offset | Default Partition Table Offset | MMU Page Size | Flash Virtual Mapping Windows (DROM / IROM) | Max Flash Size | Reference Source |
|---|---|---|---|---|---|---|---|---|---|
| **ESP32** | 2x (or 1x) Xtensa LX6 | `Xtensa:LE:32:default` (`default`) | 0 (`0x0000`) | `0x1000` (4 KiB) | `0x8000` | 64 KiB | DROM: `0x3F400000`-`0x3F800000` (4 MiB)<br>IROM: `0x400D0000`-`0x40400000` (3.25 MiB) | 16 MiB | esptool `esp32.py`, ESP-IDF `soc/esp32/include/soc/soc.h` |
| **ESP32-S2** | 1x Xtensa LX7 | `Xtensa:LE:32:default` (`default`) | 2 (`0x0002`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM: `0x3F000000`-`0x3FF80000` (15.5 MiB)<br>IROM: `0x40080000`-`0x40800000` (7.5 MiB) | 16 MiB / 1 GiB addr | esptool `esp32s2.py`, ESP-IDF `soc/esp32s2/include/soc/soc.h` |
| **ESP32-S3** | 2x Xtensa LX7 | `Xtensa:LE:32:default` (`default`) | 9 (`0x0009`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM: `0x3C000000`-`0x3E000000` (32 MiB)<br>IROM: `0x42000000`-`0x44000000` (32 MiB) | 32 MiB | esptool `esp32s3.py`, ESP-IDF `soc/esp32s3/include/soc/soc.h` |
| **ESP32-S31** | 2x RISC-V RV32 | `RISCV:LE:32:default` (`gcc`) | 32 (`0x0020`) | `0x0000` (0 B) | `0x8000` | 64 KiB | IROM: `0x40000000`-`0x54000000` (320 MiB window) | 32 MiB | esptool `esp32s31.py` MEMORY_MAP |
| **ESP32-P4** | 2x RV32IMAFCP + 1x LP | `RISCV:LE:32:default` (`gcc`) | 18 (`0x0012`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM: `0x48000000`-`0x4A000000` (32 MiB)<br>IROM: `0x40000000`-`0x44000000` (64 MiB) | 32 MiB | esptool `esp32p4.py`, ESP-IDF `soc/esp32p4/include/soc/soc.h` |
| **ESP32-C2** | 1x RV32IMC | `RISCV:LE:32:default` (`gcc`) | 12 (`0x000C`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM: `0x3C000000`-`0x3C400000` (4 MiB)<br>IROM: `0x42000000`-`0x42400000` (4 MiB) | 4 MiB | esptool `esp32c2.py`, ESP-IDF `soc/esp32c2/include/soc/soc.h` |
| **ESP32-C3** | 1x RV32IMC | `RISCV:LE:32:default` (`gcc`) | 5 (`0x0005`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM: `0x3C000000`-`0x3C800000` (8 MiB)<br>IROM: `0x42000000`-`0x42800000` (8 MiB) | 16 MiB | esptool `esp32c3.py`, ESP-IDF `soc/esp32c3/include/soc/soc.h` |
| **ESP32-C5** | 1x RV32IMAC + 1x LP | `RISCV:LE:32:default` (`gcc`) | 23 (`0x0017`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM/IROM: `0x42000000`-`0x44000000` (32 MiB) | 32 MiB | esptool `esp32c5.py`, ESP-IDF `soc/esp32c5/include/soc/soc.h` |
| **ESP32-C6** | 1x RV32IMAC + 1x LP | `RISCV:LE:32:default` (`gcc`) | 13 (`0x000D`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM/IROM: `0x42000000`-`0x43000000` (16 MiB) | 16 MiB | esptool `esp32c6.py`, ESP-IDF `soc/esp32c6/include/soc/soc.h` |
| **ESP32-C61** | 1x RV32IMAC | `RISCV:LE:32:default` (`gcc`) | 20 (`0x0014`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM/IROM: `0x42000000`-`0x44000000` (32 MiB) | 32 MiB | esptool `esp32c61.py`, ESP-IDF `soc/esp32c61/include/soc/soc.h` |
| **ESP32-E22** | 2x RV32 | `RISCV:LE:32:default` (`gcc`) | 31 (`0x001F`) | `0x0000` (0 B) | `0x8000` | 64 KiB | IROM: `0x3C000000`-`0x40000000` (64 MiB window) | 32 MiB | esptool `esp32e22.py` MEMORY_MAP |
| **ESP32-H2** | 1x RV32IMAC | `RISCV:LE:32:default` (`gcc`) | 16 (`0x0010`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM/IROM: `0x42000000`-`0x43000000` (16 MiB) | 4 MiB / 16 MiB | esptool `esp32h2.py`, ESP-IDF `soc/esp32h2/include/soc/soc.h` |
| **ESP32-H21** | 1x RV32IMAC | `RISCV:LE:32:default` (`gcc`) | 25 (`0x0019`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM/IROM: `0x42000000`-`0x43000000` (16 MiB) | 16 MiB | esptool `esp32h21.py`, ESP-IDF `soc/esp32h21/include/soc/soc.h` |
| **ESP32-H4** | 2x RV32IMAC | `RISCV:LE:32:default` (`gcc`) | 28 (`0x001C`) | `0x0000` (0 B) | `0x8000` | 64 KiB | DROM/IROM: `0x42000000`-`0x44000000` (32 MiB) | 16 MiB | esptool `esp32h4.py`, ESP-IDF `soc/esp32h4/include/soc/soc.h` |

### Critical Layout Rules:
1. **Bootloader Offset Rule**:
   - Original **ESP32** begins its second-stage bootloader at flash offset `0x1000` (4096 bytes).
   - **All other 13 series** begin their second-stage bootloader at flash offset `0x0000`.
   - Any layout parser that unconditionally reads offset 0 will fail on ESP32 captures.
2. **Partition Table Location Rules**:
   - Default offset across all 14 series is `0x8000` (32 KiB).
   - Partition tables MUST be aligned to a 4 KiB (`0x1000`) flash sector boundary.
   - Bounded partition table search MUST enforce a lower bound above the bootloader
     extent (e.g. `bootloaderOffset + bootloaderSize`) and an upper bound before
     application execution partitions (typically `0x20000` / 128 KiB).
3. **Target Chip ID Validation**:
   - The extended image header records the chip ID as a 16-bit little-endian integer
     at header offset 12.
   - Each series possesses an exact chip ID that MUST match the flash layout provider.

## 4. Per-Exact-Variant Breakdown across all 53 Silicon Parts

The catalog snapshot `catalogs/espressif/2026-09-23/catalog.json` defines exactly 53
silicon records across the 14 series. Per ESP-018 and ESP-027, every exact variant
possesses an explicit full-flash support state (`PLANNED`), documented below:

### 1. ESP32 (10 silicon parts)
- `ESP32-D0WD`: 2 cores, Xtensa LX6, QFN 5x5. No embedded flash (external flash required). State: `PLANNED`.
- `ESP32-D0WD-V3`: 2 cores, Xtensa LX6, QFN 5x5 (ECO V3). External flash. State: `PLANNED`.
- `ESP32-D0WDQ6`: 2 cores, Xtensa LX6, QFN 6x6. External flash. State: `PLANNED`.
- `ESP32-D0WDQ6-V3`: 2 cores, Xtensa LX6, QFN 6x6 (ECO V3). External flash. State: `PLANNED`.
- `ESP32-D0WDRH2-V3`: 2 cores, Xtensa LX6, QFN 5x5. Embedded 2 MiB PSRAM; external flash. State: `PLANNED`.
- `ESP32-PICO-D4`: 2 cores, Xtensa LX6, LGA 7x7 SiP. Embedded 4 MiB SPI flash. State: `PLANNED`.
- `ESP32-PICO-V3`: 2 cores, Xtensa LX6, LGA 7x7 SiP. Embedded 4 MiB SPI flash. State: `PLANNED`.
- `ESP32-PICO-V3-02`: 2 cores, Xtensa LX6, LGA 7x7 SiP. Embedded 8 MiB flash + 2 MiB PSRAM. State: `PLANNED`.
- `ESP32-S0WD`: 1 core, Xtensa LX6, QFN 5x5. External flash. State: `PLANNED`.
- `ESP32-U4WDH`: 1 core, Xtensa LX6, QFN 5x5. Embedded 4 MiB flash (high temp). State: `PLANNED`.

### 2. ESP32-S2 (4 silicon parts)
- `ESP32-S2`: 1 core, Xtensa LX7, QFN 7x7. External flash. State: `PLANNED`.
- `ESP32-S2FH4`: 1 core, Xtensa LX7, QFN 7x7. Embedded 4 MiB flash. State: `PLANNED`.
- `ESP32-S2FN4R2`: 1 core, Xtensa LX7, QFN 7x7. Embedded 4 MiB flash + 2 MiB PSRAM. State: `PLANNED`.
- `ESP32-S2R2`: 1 core, Xtensa LX7, QFN 7x7. Embedded 2 MiB PSRAM; external flash. State: `PLANNED`.

### 3. ESP32-S3 (8 silicon parts)
- `ESP32-S3`: 2 cores, Xtensa LX7, QFN 7x7. External flash. State: `PLANNED`.
- `ESP32-S3-PICO-1-N8R2`: 2 cores, Xtensa LX7, LGA 7x7. Embedded 8 MiB flash + 2 MiB PSRAM. State: `PLANNED`.
- `ESP32-S3-PICO-1-N8R8`: 2 cores, Xtensa LX7, LGA 7x7. Embedded 8 MiB flash + 8 MiB PSRAM. State: `PLANNED`.
- `ESP32-S3FH4R2`: 2 cores, Xtensa LX7, QFN 7x7. Embedded 4 MiB flash + 2 MiB PSRAM. State: `PLANNED`.
- `ESP32-S3FN8`: 2 cores, Xtensa LX7, QFN 7x7. Embedded 8 MiB flash. State: `PLANNED`.
- `ESP32-S3R16V`: 2 cores, Xtensa LX7, QFN 7x7. Embedded 16 MiB Octal PSRAM; external flash. State: `PLANNED`.
- `ESP32-S3R8`: 2 cores, Xtensa LX7, QFN 7x7. Embedded 8 MiB Octal PSRAM; external flash. State: `PLANNED`.
- `ESP32-S3RH2`: 2 cores, Xtensa LX7, QFN 7x7. Embedded 2 MiB PSRAM; external flash. State: `PLANNED`.

### 4. ESP32-S31 (2 silicon parts)
- `ESP32-S31NRV16`: 2 cores, RISC-V, QFN 8x8. Embedded 16 MiB PSRAM; external flash. State: `PLANNED`.
- `ESP32-S31NRV32`: 2 cores, RISC-V, QFN 8x8. Embedded 32 MiB PSRAM; external flash. State: `PLANNED`.

### 5. ESP32-P4 (4 silicon parts)
- `ESP32-P4NRW16`: 2 cores HP RV32 + LP, QFN 10x10. Embedded 16 MiB PSRAM; external flash. State: `PLANNED`.
- `ESP32-P4NRW16X`: 2 cores HP RV32 + LP, QFN 10x10 (extended temp). Embedded 16 MiB PSRAM. State: `PLANNED`.
- `ESP32-P4NRW32`: 2 cores HP RV32 + LP, QFN 10x10. Embedded 32 MiB PSRAM; external flash. State: `PLANNED`.
- `ESP32-P4NRW32X`: 2 cores HP RV32 + LP, QFN 10x10 (extended temp). Embedded 32 MiB PSRAM. State: `PLANNED`.

### 6. ESP32-C2 (2 silicon parts)
- `ESP8684H2X`: 1 core, RV32IMC, QFN 4x4. Embedded 2 MiB flash. State: `PLANNED`.
- `ESP8684H4X`: 1 core, RV32IMC, QFN 4x4. Embedded 4 MiB flash. State: `PLANNED`.

### 7. ESP32-C3 (6 silicon parts)
- `ESP32-C3`: 1 core, RV32IMC, QFN 5x5. External flash. State: `PLANNED`.
- `ESP32-C3FH4`: 1 core, RV32IMC, QFN 5x5. Embedded 4 MiB flash. State: `PLANNED`.
- `ESP32-C3FH4X`: 1 core, RV32IMC, QFN 5x5 (extended temp). Embedded 4 MiB flash. State: `PLANNED`.
- `ESP32-C3FH8X`: 1 core, RV32IMC, QFN 5x5 (extended temp). Embedded 8 MiB flash. State: `PLANNED`.
- `ESP32-C3FN4`: 1 core, RV32IMC, QFN 5x5. Embedded 4 MiB flash. State: `PLANNED`.
- `ESP8685H4`: 1 core, RV32IMC, QFN 4x4. Embedded 4 MiB flash. State: `PLANNED`.

### 8. ESP32-C5 (4 silicon parts)
- `ESP32-C5HF4`: 1 core, RV32IMAC, QFN 6x6. Embedded 4 MiB flash. State: `PLANNED`.
- `ESP32-C5HR2`: 1 core, RV32IMAC, QFN 6x6. Embedded 2 MiB PSRAM; external flash. State: `PLANNED`.
- `ESP32-C5HR8`: 1 core, RV32IMAC, QFN 6x6. Embedded 8 MiB PSRAM; external flash. State: `PLANNED`.
- `ESP32-C5NF8R2LA`: 1 core, RV32IMAC, LGA 6x6. Embedded 8 MiB flash + 2 MiB PSRAM. State: `PLANNED`.

### 9. ESP32-C6 (3 silicon parts)
- `ESP32-C6`: 1 core, RV32IMAC + LP, QFN 5x5. External flash. State: `PLANNED`.
- `ESP32-C6FH4`: 1 core, RV32IMAC + LP, QFN 5x5. Embedded 4 MiB flash. State: `PLANNED`.
- `ESP32-C6FH8`: 1 core, RV32IMAC + LP, QFN 5x5. Embedded 8 MiB flash. State: `PLANNED`.

### 10. ESP32-C61 (4 silicon parts)
- `ESP32-C61HF4`: 1 core, RV32IMAC, QFN 5x5. Embedded 4 MiB flash. State: `PLANNED`.
- `ESP32-C61HR2`: 1 core, RV32IMAC, QFN 5x5. Embedded 2 MiB PSRAM; external flash. State: `PLANNED`.
- `ESP32-C61HR8`: 1 core, RV32IMAC, QFN 5x5. Embedded 8 MiB PSRAM; external flash. State: `PLANNED`.
- `ESP32-C61NF8R8LA`: 1 core, RV32IMAC, LGA 5x5. Embedded 8 MiB flash + 8 MiB PSRAM. State: `PLANNED`.

### 11. ESP32-E22 (1 silicon part)
- `ESP32-E22`: 2 cores, RV32, QFN 9x9. External flash. State: `PLANNED`.

### 12. ESP32-H2 (2 silicon parts)
- `ESP32-H2FH2S`: 1 core, RV32IMAC, QFN 4x4. Embedded 2 MiB flash. State: `PLANNED`.
- `ESP32-H2FH4S`: 1 core, RV32IMAC, QFN 4x4. Embedded 4 MiB flash. State: `PLANNED`.

### 13. ESP32-H21 (1 silicon part)
- `ESP32-H21HF4`: 1 core, RV32IMAC, QFN 4x4. Embedded 4 MiB flash. State: `PLANNED`.

### 14. ESP32-H4 (2 silicon parts)
- `ESP32-H4HF4`: 2 cores, RV32IMAC, QFN 6x6. Embedded 4 MiB flash. State: `PLANNED`.
- `ESP32-H4HR2`: 2 cores, RV32IMAC, QFN 6x6. Embedded 2 MiB PSRAM; external flash. State: `PLANNED`.

## 5. Explicitly Identified Unknowns and Documentation Gaps

The technical audit identified the following explicit unknowns and documentation gaps:

1. **Preliminary and Unreleased Silicon Series**:
   - `ESP32-S31`: Officially listed in Espressif marketing catalogs with parts `ESP32-S31NRV16`
     and `ESP32-S31NRV32`, but catalog snapshot `firmwareChipId` is `UNKNOWN`. Pinned esptool
     v5.4.0 allocates chip ID 32 (`0x0020`), but vendor silicon errata and public TRMs are
     preliminary.
   - `ESP32-E22`: Catalog snapshot lists `firmwareChipId` as `UNKNOWN` and QFN 9x9 package.
     Pinned esptool v5.4.0 allocates chip ID 31 (`0x001F`). Full memory map is restricted.
   - `ESP32-H4`: Catalog snapshot lists `firmwareChipId` as 28 (`0x001C`). Dual RV32 core
     topology and cache configuration are preliminary in public documentation.
   - **Resolution Policy**: Per ESP-016 and ESP-027, preliminary chips remain `PLANNED`
     until independent reproducible hardware fixtures or official vendor tool outputs exist.

2. **Custom Partition Table Offsets (`CONFIG_PARTITION_TABLE_OFFSET`)**:
   - ESP-IDF allows projects to relocate the partition table from `0x8000` to custom sector
     offsets (e.g. `0x9000`, `0x10000`). Bounded scan handles alternate offsets when MD5
     validation succeeds, but ambiguous candidate sectors without valid MD5 records fail
     closed to avoid disassembling garbage.

3. **Flash Encryption and Ciphertext Detection**:
   - Captured full-flash images may contain encrypted partitions or an encrypted bootloader.
   - Valid MD5 records may be absent or unreadable if the partition table is encrypted.
   - Per ESP-014 and ESP-025, ciphertext MUST remain an opaque artifact and never be
     passed to a CPU disassembler.

## 6. Inventory of Current S3 Hardcoded Assumptions

The existing codebase contains several locations where ESP32-S3 specific constants or
behavior are hardcoded into shared classes. These assumptions must be extracted behind
the pure `EspFlashLayoutProvider` contract in T082:

### 1. `EspFullFlashWorkspacePlanner.java`
- **Hardcoded Chip ID Constant**:
  - Line 21: `private static final int ESP32_S3_CHIP_ID = 9;`
  - Line 112: `EspImage image = EspImageParser.parseForChip(bytes, ESP32_S3_CHIP_ID, limits, cancellation);`
  - *Impact*: Any full-flash dump from ESP32 (chip 0), ESP32-S2 (chip 2), ESP32-C3 (chip 5),
    or any other series is rejected with a chip ID mismatch error during bootloader or app extraction.
- **Hardcoded Bootloader Offset**:
  - Line 50: `EspExtractedExecutable bootloader = extractExecutable(flash, 0, table.tableFlashRange().offset(), "bootloader", ...);`
  - *Impact*: Bootloader start is hardcoded to offset `0`. For original `ESP32`, the bootloader
    starts at offset `0x1000` (4 KiB); passing offset `0` reads uninitialized flash or system headers.
- **Assumed Bootloader Extent**:
  - Line 50 uses `table.tableFlashRange().offset()` as the available byte count for the bootloader,
    assuming the bootloader occupies the entire space between 0 and the partition table (`0x8000`).

### 2. `EspPartitionTableDiscovery.java`
- **Static Default and Sector Size**:
  - Line 22: `public static final long DEFAULT_OFFSET = 0x8000;`
  - Line 24: `public static final int TABLE_SIZE = 0x1000;`
- **Unbounded Scan Search Origin**:
  - Lines 51-52: `for (long offset = 0; offset + ENTRY_SIZE <= flash.length; offset += TABLE_SIZE)`
  - *Impact*: The bounded scan starts at offset `0`, scanning every 4 KiB sector. For safe multi-target
    discovery, the search range should be constrained by the layout provider's
    `[minPartitionTableOffset, maxPartitionTableOffset]` to avoid false magic in bootloader space.

### 3. `EspApplicationImageLoader.java`
- **Hardcoded S3 Loader Invocations**:
  - Line 95: In `findSupportedLoadSpecs`, calls `EspFullFlashWorkspacePlanner.plan(input, ...)` directly.
  - Line 122: In `loadProgram`, calls `EspFullFlashWorkspacePlanner.plan(input, ...)` directly.
  - *Impact*: Because `EspFullFlashWorkspacePlanner` asserts chip ID 9, full-flash dumps for any other
    target return no load specs and fail import.
- **S3-Specific Option and Enrichment Strings**:
  - Lines 40-50: `APPLY_ESP32S3_PACKS_OPTION`, `ENRICHMENT_OPTIONS`, `ENRICHMENT_DISABLED_CODE`.
  - Lines 324-338: Conditional logic switching on `target.chipId() == 9`.
- **Single Architecture Workspace Assumption**:
  - Line 104 assumes all executables in the workspace share the load spec of the first executable.
  - Multi-core or heterogeneous targets (e.g. HP RV32 + LP core, or S3 with ULP) require independent
    per-executable language resolution.

## 7. Architectural Specification of Common Provider Interface

To satisfy ESP-022, ESP-023, and ESP-026, task T082 will refactor full-flash discovery
and workspace planning behind an extensible, pure flash-layout provider interface.

### 1. `EspFlashLayoutProfile` (Immutable Data Model)
```java
public record EspFlashLayoutProfile(
    String series,
    int chipId,
    String displayName,
    EspCpuIsa isa,
    String defaultLanguageId,
    String defaultCompilerSpecId,
    long bootloaderOffset,
    long minBootloaderLength,
    long maxBootloaderLength,
    long defaultPartitionTableOffset,
    long minPartitionTableOffset,
    long maxPartitionTableOffset,
    int mmuPageSize,
    long maxSupportedFlashSize,
    Evidence evidence
) {
    public EspFlashLayoutProfile {
        Objects.requireNonNull(series, "series");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(isa, "isa");
        Objects.requireNonNull(defaultLanguageId, "defaultLanguageId");
        Objects.requireNonNull(defaultCompilerSpecId, "defaultCompilerSpecId");
        Objects.requireNonNull(evidence, "evidence");
        if (bootloaderOffset < 0 || defaultPartitionTableOffset <= bootloaderOffset) {
            throw new IllegalArgumentException("Invalid layout offsets");
        }
    }
}
```

### 2. `EspFlashLayoutProvider` (Interface Contract)
```java
public interface EspFlashLayoutProvider {
    String providerId();
    EspFlashLayoutProfile profile();
    int chipId();
    long bootloaderOffset();
    long defaultPartitionTableOffset();
    boolean matchesChipId(int chipId);
    boolean isValidBootloaderOffset(long offset);
    boolean isValidPartitionTableOffset(long offset);
    void validateBootloader(EspImage bootloader) throws DiagnosticException;
    void validateApplication(EspImage application) throws DiagnosticException;
}
```

### 3. `EspFlashLayoutRegistry` (Discovery and Resolution)
```java
public final class EspFlashLayoutRegistry {
    public Optional<EspFlashLayoutProvider> findByChipId(int chipId);
    public Optional<EspFlashLayoutProvider> findBySeries(String series);
    public EspFlashLayoutProvider requireByChipId(int chipId);
    public List<EspFlashLayoutProvider> allProviders();
}
```

### 4. Decoupled Planning Workflow in `EspFullFlashWorkspacePlanner`
1. **Target Identification**:
   - Inspect potential bootloader candidates at candidate offsets (`0x0000` and `0x1000`).
   - If a valid `0xE9` header exists, extract chip ID from byte 12 and resolve the target
     `EspFlashLayoutProvider`.
   - If ambiguous or user-supplied, accept an explicit `EspFlashLayoutProvider`.
2. **Bounded Partition Discovery**:
   - Use `profile.defaultPartitionTableOffset()` (`0x8000`) first.
   - If absent, scan sectors strictly within `[profile.minPartitionTableOffset(), profile.maxPartitionTableOffset()]`.
3. **Multi-Program Extraction**:
   - Extract bootloader from `profile.bootloaderOffset()` with target-matched chip validation.
   - Extract unencrypted application partitions and assign roles (`FACTORY`, `OTA_0`, etc.).
   - Classify encrypted partitions and erased slots (`0xFF`) as labeled opaque data partitions.
4. **Program Language Binding**:
   - Map each executable independently using its target-specific language and address spaces.

This architecture completely eliminates hardcoded S3 assumptions from shared paths,
satisfying T080 deliverables and preparing Embedra for subsequent series implementations
in T082-T087.
