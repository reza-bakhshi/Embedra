# Nordic Semiconductor nRF Family Layout, Vector & Architectural Audit

This document records the official technical audit, capability matrix, and
architectural catalog specification for the Nordic Semiconductor nRF microcontroller
and wireless SoC family in the Embedra project, covering nRF51, nRF52, nRF53,
nRF54, and nRF91 series against pinned Nordic product specifications, nRF5 SDK /
nRF Connect SDK headers, MDK / nrfx device headers, and license terms.
It establishes the physical memory layout invariants, SoftDevice and MBR boundary
specifications, dual-core application/network topologies, ARM TrustZone security
domains, an allowlist of 21 curated exact orderable silicon parts initialized to
`PLANNED`, Ghidra language binding requirements, and exact-part matching policies
in accordance with `Embedra-SpecKit.md` (NRF-001 through NRF-010, Section 8.3A,
and Section 12).

## 1. Scope and Pinned Authoritative Baselines

Nordic Semiconductor produces low-power 2.4 GHz RF, Bluetooth Low Energy (BLE),
Thread, Zigbee, cellular IoT (LTE-M / NB-IoT), and general-purpose microcontrollers
built around ARM Cortex-M cores (Cortex-M0, Cortex-M4/M4F, and Cortex-M33).

Authoritative documentation and pinned reference baselines:
1. **nRF51 Series (ARM Cortex-M0 / ARMv6-M)**:
   - *nRF51822 Product Specification v3.3*: 256 KiB Flash, 16/32 KiB RAM, QFN48 / WLCSP.
   - *nRF51802 Product Specification v1.3*: 256 KiB Flash, 16 KiB RAM cost-optimized.
   - *nRF51422 Product Specification v3.2*: ANT + BLE multiprotocol SoC.
   - *nRF51824 Product Specification v1.1*: AEC-Q100 automotive qualified SoC.
   - Memory architecture: Code Flash starting at `0x00000000`, SRAM starting at `0x20000000`,
     Factory Information Configuration Registers (FICR) at `0x10000000`, User Information
     Configuration Registers (UICR) at `0x10001000`, Peripherals APB/AHB aperture at `0x40000000`,
     GPIO port at `0x50000000`.
2. **nRF52 Series (ARM Cortex-M4 / Cortex-M4F / ARMv7E-M)**:
   - *nRF52832 Product Specification v1.8*: Cortex-M4F (FPU), 512 KiB Flash, 64 KiB RAM, NFC-A, BLE 5.
   - *nRF52840 Product Specification v1.7*: Cortex-M4F (FPU), 1024 KiB Flash, 256 KiB RAM, USB,
     802.15.4 (Thread/Zigbee), ARM CryptoCell CC310 cryptographic engine at `0x5002A000`.
   - *nRF52810 Product Specification v1.4*: Cortex-M4 (no FPU), 192 KiB Flash, 24 KiB RAM.
   - *nRF52811 Product Specification v1.1*: Cortex-M4 (no FPU), 192 KiB Flash, 24 KiB RAM, Direction Finding (AoA/AoD).
   - *nRF52820 Product Specification v1.2*: Cortex-M4, 256 KiB Flash, 32 KiB RAM, USB 2.0 full speed.
   - *nRF52833 Product Specification v1.5*: Cortex-M4F (FPU), 512 KiB Flash, 128 KiB RAM, USB, Extended temperature range.
3. **nRF53 Series (Dual ARM Cortex-M33 / ARMv8-M Mainline)**:
   - *nRF5340 Product Specification v1.3*:
     - **Application Core**: Cortex-M33 with FPU, DSP, TrustZone, 128 MHz, 1024 KiB Flash (`0x00000000`),
       512 KiB RAM (`0x20000000`), CryptoCell CC312 at `0x50840000`, SPU (System Protection Unit).
     - **Network Core**: Cortex-M33 without FPU, 64 MHz, 256 KiB Flash (`0x01000000`),
       64 KiB RAM (`0x21000000`), dedicated radio and network peripherals (`0x41000000`).
     - Inter-Processor Communication (IPC) hardware channels between cores.
4. **nRF54 Series (ARM Cortex-M33 + RISC-V Coprocessor)**:
   - *nRF54L15 Product Brief & Architecture Specification*: Next-generation ultra-low-power SoC,
     Cortex-M33 at 128 MHz + RISC-V coprocessor, 1.5 MiB Non-Volatile Memory (RRAM) at `0x00000000`,
     256 KiB RAM at `0x20000000`.
   - *nRF54H20 Product Brief & Architecture Specification*: Multiple Cortex-M33 cores + RISC-V peripherals,
     2 MiB RRAM, 1 MiB RAM, advanced hardware security.
5. **nRF91 Series (ARM Cortex-M33 Cellular IoT & TrustZone)**:
   - *nRF9160 Product Specification v2.1*: Cortex-M33 with FPU, TrustZone-M, 1024 KiB Flash,
     256 KiB RAM, integrated LTE-M / NB-IoT modem subsystem, GPS, ARM CryptoCell CC312 at `0x50840000`.
   - *nRF9161 Product Specification v1.1*: LTE-M / NB-IoT / DECT NR+ smart cellular IoT module.

## 2. Documentation Provenance & License Analysis

In accordance with CORE-013, NRF-007, and repository license integrity policies:
1. **Datasheets & Product Specifications**:
   - Copyright (C) Nordic Semiconductor ASA. Factual hardware layout parameters, register
     base addresses, bit positions, and memory map invariants constitute non-copyrightable facts.
2. **MDK & nrfx Device Headers**:
   - Published under permissive BSD-3-Clause and Apache-2.0 licenses by Nordic Semiconductor.
   - Pinned source: Nordic nrfx v3.5.0 repository (`https://github.com/NordicSemiconductor/nrfx`).
   - SVD register definition files provided by Nordic are licensed under Apache-2.0 or BSD-3-Clause,
     free of GPL or non-commercial restrictions.
3. **SoftDevice Binary Images & Specifications**:
   - SoftDevice specifications (S110, S112, S130, S132, S140) define public memory layout contracts
     and SVC call tables.
   - Embedra test fixtures use clean synthetic redistributable binary/HEX images generated
     without copying proprietary binary blobs from Nordic distributions.

## 3. Unified Physical Memory Layout & Invariants per Series

Across the entire Nordic nRF portfolio, physical memory spaces maintain predictable
architectural anchors:

| Region | Base Address | Typical Size | Description |
|---|---|---|---|
| **Code Flash (Internal)** | `0x00000000` | 128 KiB to 2 MiB | Executable non-volatile memory containing MBR, SoftDevice, or App |
| **SRAM (Internal)** | `0x20000000` | 16 KiB to 1024 KiB | General-purpose SRAM for data, stack, and heap |
| **FICR (nRF51 / nRF52)** | `0x10000000` | 256 B to 2 KiB | Factory Information Configuration Registers (Device ID, MAC, trims) |
| **UICR (nRF51 / nRF52)** | `0x10001000` | 256 B to 1 KiB | User Information Configuration Registers (Bootloader address, PSEL, APPROTECT) |
| **FICR (nRF53 / nRF91 / nRF54)** | `0x00FF0000` | 2 KiB | Modern factory info registers (Secure/Local flash info space) |
| **UICR (nRF53 / nRF91 / nRF54)** | `0x00FF8000` | 2 KiB | Modern user info registers (Secure/Local flash info space) |
| **Peripherals (APB/AHB)** | `0x40000000` | 256 KiB - 1 MiB | Non-Secure / General peripheral MMIO aperture |
| **Peripherals (Secure / Port)** | `0x50000000` | 256 KiB - 1 MiB | Secure peripheral MMIO aperture (GPIO, SPU, TrustZone peripherals) |
| **CryptoCell CC310 (nRF52840)** | `0x5002A000` | 4 KiB | Hardware cryptographic accelerator (AES, SHA, RSA, ECC, TRNG) |
| **CryptoCell CC312 (nRF5340 / nRF9160)** | `0x50840000` | 64 KiB | Advanced hardware cryptographic engine (ChaCha-Poly, AES, ECC, etc.) |
| **QSPI External Flash XIP** | `0x12000000` | Up to 128 MiB | External SPI/QSPI NOR Flash execution-in-place aperture (nRF52840) |

## 4. SoftDevice Architecture, MBR, and Application Offset Boundaries

Nordic BLE applications on nRF51 and nRF52 commonly employ precompiled wireless protocol
stacks known as **SoftDevices** (e.g., S110, S112, S130, S132, S140):
1. **Master Boot Record (MBR)**:
   - Resides at `0x00000000` - `0x00000FFF` (4 KiB).
   - Manages vector forwarding to the SoftDevice or Application, and supports in-field firmware updates.
2. **SoftDevice Partition**:
   - Starts at `0x00001000` directly above the MBR.
   - Intercepts hardware interrupts, SVC calls (Supervisor Calls), and radio peripherals.
3. **Application Partition & Vector Relocation**:
   - Located at a fixed offset immediately following the SoftDevice.
   - For **S112 v7** on nRF52810/832: Application starts at **`0x00019000`**.
   - For **S132 v7** on nRF52832: Application starts at **`0x00026000`**.
   - For **S140 v7** on nRF52840: Application starts at **`0x00027000`**.
   - On Cortex-M4 (nRF52), the VTOR register (`0xE000ED08`) is pointed to the application vector table.
4. **Bootloader Partition**:
   - Typically resides at the top of Flash (e.g. `0x00078000` for 512K nRF52832, `0x000F8000` for 1MB nRF52840).
   - Bootloader start address is programmed into the UICR `BOOTLOADERADDR` field (`0x10001014` / `0x10001018`).

## 5. Dual-Core Topologies (nRF5340 Architecture)

The nRF5340 integrates two asynchronous ARM Cortex-M33 cores:
1. **Application Core**:
   - High-performance 128 MHz Cortex-M33 with FPU, DSP, ARM TrustZone, and 8 KiB I-Cache.
   - 1 MiB Flash (`0x00000000` - `0x000FFFFF`) and 512 KiB SRAM (`0x20000000` - `0x2007FFFF`).
   - Owns high-speed USB, QSPI, CryptoCell CC312, and system power management.
2. **Network Core**:
   - Ultra-low-power 64 MHz Cortex-M33 without FPU, optimized for radio protocol handling.
   - 256 KiB Flash (global map: `0x01000000` - `0x0103FFFF`, local alias: `0x00000000` - `0x0003FFFF`).
   - 64 KiB SRAM (global map: `0x21000000` - `0x2100FFFF`, local alias: `0x20000000` - `0x2000FFFF`).
   - Owns the 2.4 GHz radio transceiver and local network timers/RTC.
3. **Inter-Core Communication**:
   - IPC (Inter-Processor Communication) peripheral provides bidirectional hardware signaling
     between Application and Network cores.

## 6. ARM TrustZone Security Domains (nRF9160 & nRF5340)

ARM TrustZone technology divides the memory map and peripheral spaces into **Secure** and
**Non-Secure** execution domains:
1. **System Protection Unit (SPU)**:
   - Peripheral at `0x50003000` (Secure) configuring Flash regions (in 32 KiB blocks),
     SRAM regions (in 8 KiB blocks), and peripheral access permissions.
2. **Memory Partitioning**:
   - Secure code runs from lower Flash and manages cryptographic keys, Secure Boot, and
     modem/network credentials.
   - Non-Secure code (such as Zephyr RTOS or customer application) runs from upper Flash
     and accesses peripherals via Non-Secure Callable (NSC) veneer gateways.
3. **Peripheral Apertures**:
   - Secure MMIO: `0x50000000` - `0x5003FFFF`
   - Non-Secure MMIO: `0x40000000` - `0x4003FFFF`
   - Unprivileged or unauthorized access triggers SecureFault / HardFault exceptions.

## 7. Curated Exact-Part Allowlist (21 Silicon Parts)

The catalog covers 21 curated exact orderable silicon parts across all 5 series:

| Exact Part | Series | Core | FPU | Flash | RAM | Package | Peripherals / Features |
|---|---|---|---|---|---|---|---|
| `nRF51822-QFAA` | nRF51 | Cortex-M0 | No | 256 KiB | 16 KiB | QFN48 | BLE 4.x, 2.4 GHz RF, APB MMIO |
| `nRF51822-QFAC` | nRF51 | Cortex-M0 | No | 256 KiB | 32 KiB | QFN48 | BLE 4.x, 2.4 GHz RF, 32K RAM |
| `nRF51802-QFAA` | nRF51 | Cortex-M0 | No | 256 KiB | 16 KiB | QFN48 | Cost-optimized BLE SoC |
| `nRF51422-QFAA` | nRF51 | Cortex-M0 | No | 256 KiB | 16 KiB | QFN48 | ANT + BLE multiprotocol |
| `nRF51824-QFAA` | nRF51 | Cortex-M0 | No | 256 KiB | 16 KiB | QFN48 | Automotive AEC-Q100 |
| `nRF52832-QFAA` | nRF52 | Cortex-M4F | Yes | 512 KiB | 64 KiB | QFN48 | BLE 5, NFC, EasyDMA, S132 |
| `nRF52832-CIAA` | nRF52 | Cortex-M4F | Yes | 512 KiB | 64 KiB | WLCSP50 | Miniature package BLE 5, NFC |
| `nRF52840-QIAA` | nRF52 | Cortex-M4F | Yes | 1024 KiB | 256 KiB | aQFN73 | BLE 5, Thread, Zigbee, USB, CryptoCell CC310 |
| `nRF52840-CKAA` | nRF52 | Cortex-M4F | Yes | 1024 KiB | 256 KiB | WLCSP93 | High-density WLCSP, CryptoCell CC310 |
| `nRF52810-QCAA` | nRF52 | Cortex-M4 | No | 192 KiB | 24 KiB | QFN32 | Cost-effective BLE 5, S112 |
| `nRF52810-QFAA` | nRF52 | Cortex-M4 | No | 192 KiB | 24 KiB | QFN48 | Cost-effective BLE 5, 32 GPIOs |
| `nRF52811-QCAA` | nRF52 | Cortex-M4 | No | 192 KiB | 24 KiB | QFN32 | BLE 5.1 Direction Finding (AoA/AoD), 802.15.4 |
| `nRF52820-QDAA` | nRF52 | Cortex-M4 | No | 256 KiB | 32 KiB | QFN40 | BLE 5.2, USB 2.0 full speed |
| `nRF52833-QIAA` | nRF52 | Cortex-M4F | Yes | 512 KiB | 128 KiB | aQFN73 | USB, Extended temp (-40C to 105C), S140 |
| `nRF52833-CJAA` | nRF52 | Cortex-M4F | Yes | 512 KiB | 128 KiB | WLCSP51 | Ultra-compact WLCSP, USB, NFC |
| `nRF5340-QKAA` | nRF53 | Dual M33 | Yes (App) | 1280 KiB | 576 KiB | aQFN94 | Dual-core App (1MB/512K) + Net (256K/64K), CC312 |
| `nRF5340-CLAA` | nRF53 | Dual M33 | Yes (App) | 1280 KiB | 576 KiB | WLCSP95 | Miniature dual-core WLCSP, CC312 |
| `nRF54L15` | nRF54 | M33+RV32 | Yes | 1536 KiB | 256 KiB | QFN48 | 1.5MB RRAM, RISC-V coprocessor |
| `nRF54H20` | nRF54 | Multi M33 | Yes | 2048 KiB | 1024 KiB | BGA | Multiple M33 + RV32, 2MB RRAM, 1MB RAM |
| `nRF9160-SICA` | nRF91 | Cortex-M33 | Yes | 1024 KiB | 256 KiB | LGA | LTE-M / NB-IoT / GPS, TrustZone, CC312 |
| `nRF9161-SICA` | nRF91 | Cortex-M33 | Yes | 1024 KiB | 256 KiB | LGA | LTE-M / NB-IoT / DECT NR+, TrustZone, CC312 |

## 8. Support State & Strict Allowlist Policy

In accordance with NRF-010 and the project's zero-unverified-promotion principle:
1. **Initial Support State**:
   - All 21 curated parts initialize to **`supportState = "PLANNED"`**.
   - No part shall be promoted to `EXPERIMENTAL` or `SUPPORTED` without passing the complete
     multi-program import, vector table relocation, and headless verification test suite (T098-T103).
2. **Exact-Part Matching Policy**:
   - Only exact part identifiers (e.g. `nRF52840-QIAA`) are permitted.
   - Wildcards (`*`, `?`), bare series prefixes (`nRF52`, `nRF53`), or fuzzy approximations are
     rejected at catalog query time.

## 9. Ghidra Language Binding Specification

Ghidra maps the ARM processor architectures across Nordic series as follows:

| Series | Core | Ghidra Language ID | Compiler Spec ID | Address Alignment |
|---|---|---|---|---|
| **nRF51** | Cortex-M0 | `ARM:LE:32:v6M` | `default` | 2 bytes (Thumb-only) |
| **nRF52** | Cortex-M4 / Cortex-M4F | `ARM:LE:32:v7EM` | `default` | 2 bytes (Thumb-2) |
| **nRF53 (App)** | Cortex-M33 | `ARM:LE:32:v8M` | `default` | 2 bytes (Thumb-2 / TrustZone) |
| **nRF53 (Net)** | Cortex-M33 | `ARM:LE:32:v8M` | `default` | 2 bytes (Thumb-2) |
| **nRF54** | Cortex-M33 / RV32 | `ARM:LE:32:v8M` | `default` | 2 bytes / 4 bytes |
| **nRF91** | Cortex-M33 | `ARM:LE:32:v8M` | `default` | 2 bytes (TrustZone) |

## 10. Unknowns, Documentation Gaps & Preliminary Notes

1. **nRF54 Hardware Peripherals**:
   - nRF54L15 and nRF54H20 are newly released silicons. Register schemas and SVD definitions
     will be integrated from public nRF Connect SDK releases in T100.
2. **CryptoCell Driver Interfaces**:
   - Hardware register registers for CryptoCell CC310 and CC312 are memory-mapped at `0x5002A000`
     and `0x50840000`, but deep cryptographic operations are driven through opaque library APIs
     (Nordic nrf_cc310 / nrf_cc312). Embedra will treat these apertures as MMIO register blocks.
3. **SoftDevice Vector Table Forwarding**:
   - On Cortex-M0 (nRF51), VTOR does not exist in hardware. SoftDevice MBR forwards interrupts
     via software trampoline. On Cortex-M4 (nRF52), VTOR register relocation is native.
