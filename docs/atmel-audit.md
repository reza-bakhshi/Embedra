# Atmel / Microchip (AVR and SAM) Architecture, Memory & Layout Audit

This document records the official technical audit, capability matrix, and
architectural catalog specification for the Atmel / Microchip microcontroller family
in the Embedra project, covering 8-bit AVR microcontrollers (classic megaAVR,
classic tinyAVR, and modern AVR-0/1/2-series / AVR-DA/DB/DD) and 32-bit ARM-based
SAM microcontrollers (SAMD Cortex-M0+, SAME/SAMS/SAMV Cortex-M7, SAML/SAMC Cortex-M0+,
and legacy SAM3 Cortex-M3) against pinned Microchip Device Family Packs (DFP),
ATDF schemas, official datasheets, and license terms.
It establishes the Harvard address space separation for 8-bit AVR (`code`, `data`, `eeprom`,
`io`), 32-bit linear physical memory maps for SAM, vector table stride invariants
(2-byte `RJMP` vs 4-byte `JMP`), bootloader boundary partitioning (Optiboot, SAM-BA),
fuse and lock bit schemas, an allowlist of 27 curated exact orderable silicon parts
initialized to `PLANNED`, Ghidra language binding requirements, and exact-part
matching policies in accordance with `Embedra-SpecKit.md` (ATMEL-001 through ATMEL-010,
Section 8.3B, and Section 12).

---

## 1. Scope and Pinned Authoritative Baselines

Microchip Technology Inc. (incorporating Atmel Corporation) produces two major
microcontroller families widely utilized across consumer, maker, industrial,
and automotive domains:

1. **8-bit AVR RISC Family**:
   - **Classic megaAVR (`ATmega`)**:
     - *ATmega328P*: 32 KiB Flash, 2 KiB SRAM, 1 KiB EEPROM, 26 vectors (4-byte `JMP`), DIP28/TQFP32. Arduino Uno MCU. Microchip DS40002061B / Atmel 8271.
     - *ATmega2560*: 256 KiB Flash (requires 3-byte PC / 24-bit addressing), 8 KiB SRAM, 4 KiB EEPROM, 57 vectors (4-byte `JMP`), TQFP100. Arduino Mega 2560 MCU. Microchip DS40002211A / Atmel 2549.
     - *ATmega32U4*: 32 KiB Flash, 2.5 KiB SRAM, 1 KiB EEPROM, full-speed USB 2.0 controller, 43 vectors (4-byte `JMP`), TQFP44/QFN44. Arduino Leonardo/Micro MCU. Microchip DS40002056B.
     - *ATmega128*: 128 KiB Flash, 4 KiB SRAM, 4 KiB EEPROM, 35 vectors (4-byte `JMP`), TQFP64. Microchip DS40002196A.
     - *ATmega168P*: 16 KiB Flash, 1 KiB SRAM, 512 B EEPROM, 26 vectors (4-byte `JMP`). Microchip DS40002061B.
     - *ATmega88P*: 8 KiB Flash, 1 KiB SRAM, 512 B EEPROM, 26 vectors (2-byte `RJMP`). Microchip DS40002061B.
     - *ATmega8A*: 8 KiB Flash, 1 KiB SRAM, 512 B EEPROM, 19 vectors (2-byte `RJMP`). Microchip DS40001977A.
   - **Classic tinyAVR (`ATtiny`)**:
     - *ATtiny85*: 8 KiB Flash, 512 B SRAM, 512 B EEPROM, 15 vectors (2-byte `RJMP`), DIP8/SOIC8. Digispark MCU. Microchip DS40001509B.
     - *ATtiny45*: 4 KiB Flash, 256 B SRAM, 256 B EEPROM, 15 vectors (2-byte `RJMP`). Microchip DS40001509B.
     - *ATtiny13A*: 1 KiB Flash, 64 B SRAM, 64 B EEPROM, 10 vectors (2-byte `RJMP`). Microchip DS40002307A.
     - *ATtiny84*: 8 KiB Flash, 512 B SRAM, 512 B EEPROM, 17 vectors (2-byte `RJMP`), SOIC14/DIP14. Microchip DS40001500B.
     - *ATtiny2313A*: 2 KiB Flash, 128 B SRAM, 128 B EEPROM, 19 vectors (2-byte `RJMP`), SOIC20/DIP20. Microchip DS40002166A.
     - *ATtiny1614* (tinyAVR 1-series, AVRxt core): 16 KiB Flash, 2 KiB SRAM, 256 B EEPROM, UPDI programming, unified memory. Microchip DS40001994B.
   - **Modern AVR-Dx Series (AVRxt Core)**:
     - *AVR128DA48*: 128 KiB Flash, 16 KiB SRAM, 512 B EEPROM, Flash aliased into data space at `0x8000`, UPDI, Core Independent Peripherals. Microchip DS40002183B.
     - *AVR128DB48*: 128 KiB Flash, 16 KiB SRAM, 512 B EEPROM, Multi-Voltage I/O (MVIO), OpAmps. Microchip DS40002247B.
     - *AVR64DA32*: 64 KiB Flash, 8 KiB SRAM, 512 B EEPROM. Microchip DS40002183B.
     - *AVR32DA28*: 32 KiB Flash, 4 KiB SRAM, 512 B EEPROM. Microchip DS40002183B.
     - *AVR128DD48*: 128 KiB Flash, 16 KiB SRAM, 512 B EEPROM, MVIO. Microchip DS40002315B.

2. **32-bit ARM-Based SAM Family**:
   - **SAMD Series (ARM Cortex-M0+ / Cortex-M4F)**:
     - *SAMD21G18A*: Cortex-M0+, 256 KiB Flash at `0x00000000`, 32 KiB SRAM at `0x20000000`, SAM-BA boot ROM, USB device/host. Arduino Zero / MKR MCU. Microchip DS40001882G.
     - *SAMD21E18A*: Cortex-M0+, 256 KiB Flash, 32 KiB SRAM, 32-pin package. Microchip DS40001882G.
     - *SAMD51J19A*: Cortex-M4F (120 MHz, FPU), 512 KiB Flash, 192 KiB SRAM, QSPI, dual CAN, PUKCC/ICM/TRNG crypto. Microchip DS40001995E.
     - *SAML21J18B*: Cortex-M0+, 256 KiB Flash, 32 KiB SRAM, ultra-low power (PICO Power), AES, TRNG. Microchip DS60001477C.
     - *SAMC21J18A*: Cortex-M0+, 256 KiB Flash, 32 KiB SRAM, 5V operating voltage, dual CAN-FD. Microchip DS60001479C.
   - **SAME / SAMS / SAMV / SAM3 Series (ARM Cortex-M7 / Cortex-M3)**:
     - *SAME70Q21*: Cortex-M7 (300 MHz, DP-FPU), 2048 KiB Flash at `0x00400000`, 384 KiB SRAM at `0x20400000`, SAM-BA boot ROM at `0x00800000`, 10/100 Ethernet MAC, USB HS, CAN-FD, AES, TRNG. Microchip DS60001527E.
     - *SAMS70N21*: Cortex-M7 (300 MHz), 2048 KiB Flash at `0x00400000`, 384 KiB SRAM at `0x20400000`. Microchip DS60001527E.
     - *SAMV71Q21*: Cortex-M7 (300 MHz), 2048 KiB Flash at `0x00400000`, 384 KiB SRAM at `0x20400000`, automotive grade, Ethernet AVB, MediaLB. Microchip DS60001527E.
     - *SAM3X8E*: Cortex-M3 (84 MHz), 512 KiB Flash (dual-bank 2x256 KiB at `0x00080000` / `0x000C0000`), 96 KiB SRAM at `0x20000000`, SAM-BA boot ROM at `0x00100000`. Arduino Due MCU. Microchip DS11057C.

---

## 2. Documentation Provenance & License Analysis

In accordance with CORE-013, ATMEL-008, ATMEL-010, and repository licensing integrity:

1. **Datasheets & Product Specifications**:
   - Copyright (C) Microchip Technology Inc. / Atmel Corporation. Factual register addresses,
     memory map limits, bit definitions, vector counts, and electrical specifications constitute
     non-copyrightable technical facts under international intellectual property law.
2. **Device Family Packs (DFP) and ATDF / SVD Schemas**:
   - Microchip Device Family Packs are published for GCC, MPLAB X, Keil MDK, and CMSIS pack managers
     under Apache-2.0, BSD-3-Clause, or explicit redistributable DFP license terms.
   - Embedra ingests and transforms ATDF (Atmel Device Description) XML and CMSIS-SVD files
     into pure internal schemas without bundling non-distributable proprietary blobs.
3. **Synthetic Test Fixtures**:
   - All test fixtures and oracles generated by Embedra are independently authored synthetic
     binaries, Intel HEX files, and ELF objects containing zero proprietary Microchip code.

---

## 3. Harvard Architecture vs Linear 32-bit Architecture

### 3.1 8-bit AVR Modified Harvard Architecture

8-bit AVR microcontrollers utilize a modified Harvard architecture with physically separate
memories and distinct addressing mechanisms:

```
+-----------------------------------------------------------------------------+
|                                8-bit AVR SPACES                             |
+-----------------------------------------------------------------------------+
| 1. Program Flash (code)      | Base 0x0000, Word-addressed PC (PC = Addr/2) |
|    - Vectors                 | 0x0000 .. (VectorCount * Stride - 1)          |
|    - Application             | After vector table up to Boot section        |
|    - Bootloader Section      | High Flash (e.g. 0x7E00 on ATmega328P)       |
+------------------------------+----------------------------------------------+
| 2. Data Space (data)         | Byte-addressed                               |
|    - 0x0000 .. 0x001F        | 32 General-Purpose Working Registers (R0-R31)|
|    - 0x0020 .. 0x005F        | 64 Standard I/O Registers (Port 0x00..0x3F)  |
|    - 0x0060 .. 0x00FF/0x01FF | Extended I/O Registers (on larger megaAVR)   |
|    - 0x0100 / 0x0200 .. End  | Internal SRAM (Heap / Stack)                 |
+------------------------------+----------------------------------------------+
| 3. I/O Space (io)            | 6-bit direct I/O address (0x00 .. 0x3F)      |
|                              | Used by IN, OUT, CBI, SBI, SBIC, SBIS        |
+------------------------------+----------------------------------------------+
| 4. Non-Volatile EEPROM       | Byte-addressed (0x0000 .. eepromBytes - 1)   |
|    (eeprom)                  | Accessed via EECR, EEAR, EEDR registers      |
+-----------------------------------------------------------------------------+
```

#### Modern AVR-Dx Unified Memory View (AVRxt Core)
In the modern AVR-Dx family (e.g., `AVR128DA48`), data space is organized as a unified
linear map:
- `0x0000 - 0x0FFF`: Peripheral MMIO registers.
- `0x1000 - 0x13FF`: VPORTs (Virtual Ports).
- `0x1400 - 0x15FF`: EEPROM.
- `0x1600 - 0x17FF`: User Row (signature / calibration).
- `0x4000 - 0x7FFF`: Internal SRAM (16 KiB).
- `0x8000 - 0xFFFF`: Flash Program Memory Data Space Alias (32 KiB window into Flash,
  allowing constant reading via standard LD/LDS instructions without LPM).

### 3.2 32-bit SAM ARM Cortex-M Linear Architecture

In contrast, 32-bit SAM microcontrollers follow the standard ARM linear 32-bit physical address space:

```
+------------------+------------------+------------------+--------------------+
| Address Space    | SAMD21 (CM0+)    | SAME70 (CM7)     | SAM3X8E (CM3)      |
+------------------+------------------+------------------+--------------------+
| Code Flash       | 0x00000000       | 0x00400000       | 0x00080000         |
| SRAM             | 0x20000000       | 0x20400000       | 0x20000000         |
| Peripherals      | 0x40000000       | 0x40000000       | 0x40000000         |
| SAM-BA ROM       | 0x00000000 (map) | 0x00800000       | 0x00100000         |
| System (PPB)     | 0xE0000000       | 0xE0000000       | 0xE0000000         |
+------------------+------------------+------------------+--------------------+
```

---

## 4. Interrupt Vector Tables and Entry Points

### 4.1 AVR Interrupt Vector Table Invariants

The AVR interrupt vector table begins at `0x0000` (or the bootloader reset address
when `BOOTRST` is programmed):

1. **Vector Instruction Size & Stride**:
   - **2-Byte `RJMP` Vector Stride**: Devices with Flash $\le$ 8 KiB (e.g., `ATtiny85`,
     `ATtiny13A`, `ATtiny84`, `ATmega8A`, `ATmega88P`) use relative jump (`RJMP <offset>`)
     instructions (opcode `0xCxxx`). Each entry is 2 bytes (1 word).
   - **4-Byte `JMP` Vector Stride**: Devices with Flash > 8 KiB (e.g., `ATmega328P`,
     `ATmega2560`, `ATmega32U4`, `ATmega128`) require full 2-word absolute jump
     (`JMP <address>`) instructions (opcode `0x940C <addr_low> <addr_high>`).
     Each entry is 4 bytes (2 words).
   - **Modern AVR-Dx (AVRxt)**: Vector table entries are 4 bytes (`JMP` instruction).

2. **Bootloader Reset Redirection (`BOOTRST`)**:
   - When the `BOOTRST` fuse is unprogrammed (`1`), execution begins at `0x0000` (Application).
   - When the `BOOTRST` fuse is programmed (`0`), execution begins at the start address of
     the boot flash section specified by `BOOTSZ0`/`BOOTSZ1` (e.g., `0x7E00` on `ATmega328P`).
   - The `IVSEL` bit in `MCUCR` dynamically relocates interrupt vector dispatch to the boot
     section boundary.

### 4.2 SAM Cortex-M Interrupt Vector Table Invariants

SAM devices adhere strictly to ARM Cortex-M vector table format:
- Offset `0x00`: Initial Main Stack Pointer (`MSP`), pointing to top of SRAM.
- Offset `0x04`: Reset Handler pointer (bit 0 set for Thumb state).
- Offsets `0x08 - 0x3C`: Cortex-M system exception handlers (NMI, HardFault, MemManage, BusFault, UsageFault, SVCall, SysTick).
- Offsets `0x40+`: Peripheral interrupt vectors (IRQ0 through IRQn).

---

## 5. Non-Volatile Configuration: Fuses and Lock Bits

Configuration memory controls critical chip parameters prior to CPU execution:

### 5.1 Classic AVR Fuses and Lock Bits
1. **Low Fuse Byte (`LOW`)**:
   - Clock source selection (internal RC, external crystal, PLL).
   - Clock output (`CKOUT`), startup time delays (`SUT[1:0]`), divide-by-8 (`CKDIV8`).
2. **High Fuse Byte (`HIGH`)**:
   - Reset pin function (`RSTDISBL`).
   - Debug interfaces (`DWEN` debugWIRE, `JTAGEN` JTAG enable).
   - Watchdog timer always-on (`WDTON`).
   - EEPROM erase preservation during chip erase (`EESAVE`).
   - Boot section size (`BOOTSZ[1:0]`) and boot reset vector enable (`BOOTRST`).
3. **Extended Fuse Byte (`EXTENDED`)**:
   - Brown-out Detector enable and threshold levels (`BODLEVEL[2:0]`).
4. **Lock Bits (`LOCK`)**:
   - Memory verification protection (`BLB12`, `BLB11`, `BLB02`, `BLB01`, `LB2`, `LB1`),
     preventing unauthorized Flash/EEPROM readback or modification.

### 5.2 Modern AVR-Dx Fuse Registers
Configured as individual non-volatile registers in the User Row / Fuse space:
- `WDTCFG`: Watchdog timer configuration.
- `BODCFG`: Brown-out detector configuration.
- `OSCCFG`: High-frequency oscillator frequency (16/20/24 MHz).
- `SYSCFG0`: Reset pin mode, UPDI pin enable, CRC check on reset.
- `SYSCFG1`: SUT startup time delay.
- `CODESIZE`: Size of application code section in 256-byte blocks.
- `BOOTSIZE`: Size of boot section in 256-byte blocks.

### 5.3 SAM Non-Volatile Configuration
- **SAMD21 / SAMD51**: NVM User Row (`0x00804000`) containing `BOOTPROT` (boot section write protection),
  `EEPROM` emulated size, `BOD33` calibration, and `SECURITY_BIT` (disables SWD/JTAG debugger access).
- **SAME70 / SAM3X**: General-Purpose NVM (`GPNVM`) bits:
  - `GPNVM0`: Security bit (cleared = JTAG locked).
  - `GPNVM1`: Boot Mode select (`0` = Boot from SAM-BA ROM, `1` = Boot from internal Flash).
  - `GPNVM7` (SAME70): TCM size configuration.

---

## 6. Bootloader Architecture and Fingerprinting

1. **Optiboot (ATmega328P, ATmega168P, ATmega88P)**:
   - Size: 512 bytes (located at `0x7E00` on ATmega328P).
   - Protocol: STK500v1 over hardware USART0 (115200 baud).
   - Fingerprint: Short vector table at `0x7E00`, initialization of USART0 registers (`UBRR0H`, `UBRR0L`, `UCSR0B`),
     and magic command responses `0x14 0x10` (InSync / OK).
2. **STK500boot (ATmega2560, ATmega128)**:
   - Size: 4 KiB - 8 KiB (located at `0x3E000` on ATmega2560).
   - Protocol: STK500v2 over USART0 (supports > 64 KiB Flash via extended address commands).
3. **Caterina / DFU Bootloader (ATmega32U4)**:
   - Size: 4 KiB (located at `0x7000`).
   - Protocol: USB CDC serial or USB DFU device class.
4. **SAM-BA ROM Bootloader (SAMD, SAME, SAM3)**:
   - Factory ROM bootloader burned into dedicated ROM (`0x00800000` on SAME70, `0x00100000` on SAM3X8E).
   - Activated when Flash is blank or when GPNVM1 / remap bit indicates ROM boot.
   - Provides USB and USART communication with Microchip SAM-BA host tool.

---

## 7. Curated Exact-Part Allowlist & Capability Matrix

The official dated catalog snapshot under `catalogs/atmel/2026-10-14/catalog.json`
inventories 27 curated exact silicon parts. In strict compliance with `ATMEL-010`,
all parts initialize in the `PLANNED` state:

| Exact Part | Family | Series | Core | Ghidra Language | Flash | SRAM | EEPROM | Vector Stride | Status |
|---|---|---|---|---|---|---|---|---|---|
| **ATmega328P** | AVR | ATmega | AVR RISC | `avr8:LE:16:default` | 32 KiB | 2 KiB | 1024 B | 4 B (`JMP`) | `PLANNED` |
| **ATmega2560** | AVR | ATmega | AVR RISC | `avr8:LE:24:default` | 256 KiB | 8 KiB | 4096 B | 4 B (`JMP`) | `PLANNED` |
| **ATmega32U4** | AVR | ATmega | AVR RISC | `avr8:LE:16:default` | 32 KiB | 2.5 KiB | 1024 B | 4 B (`JMP`) | `PLANNED` |
| **ATmega128** | AVR | ATmega | AVR RISC | `avr8:LE:16:default` | 128 KiB | 4 KiB | 4096 B | 4 B (`JMP`) | `PLANNED` |
| **ATmega168P** | AVR | ATmega | AVR RISC | `avr8:LE:16:default` | 16 KiB | 1 KiB | 512 B | 4 B (`JMP`) | `PLANNED` |
| **ATmega88P** | AVR | ATmega | AVR RISC | `avr8:LE:16:default` | 8 KiB | 1 KiB | 512 B | 2 B (`RJMP`) | `PLANNED` |
| **ATmega8A** | AVR | ATmega | AVR RISC | `avr8:LE:16:default` | 8 KiB | 1 KiB | 512 B | 2 B (`RJMP`) | `PLANNED` |
| **ATtiny85** | AVR | ATtiny | AVR RISC | `avr8:LE:16:default` | 8 KiB | 512 B | 512 B | 2 B (`RJMP`) | `PLANNED` |
| **ATtiny45** | AVR | ATtiny | AVR RISC | `avr8:LE:16:default` | 4 KiB | 256 B | 256 B | 2 B (`RJMP`) | `PLANNED` |
| **ATtiny13A** | AVR | ATtiny | AVR RISC | `avr8:LE:16:default` | 1 KiB | 64 B | 64 B | 2 B (`RJMP`) | `PLANNED` |
| **ATtiny84** | AVR | ATtiny | AVR RISC | `avr8:LE:16:default` | 8 KiB | 512 B | 512 B | 2 B (`RJMP`) | `PLANNED` |
| **ATtiny2313A** | AVR | ATtiny | AVR RISC | `avr8:LE:16:default` | 2 KiB | 128 B | 128 B | 2 B (`RJMP`) | `PLANNED` |
| **ATtiny1614** | AVR | ATtiny | AVRxt | `avr8:LE:24:xmega` | 16 KiB | 2 KiB | 256 B | 4 B (`JMP`) | `PLANNED` |
| **AVR128DA48** | AVR | AVR-Dx | AVRxt | `avr8:LE:24:xmega` | 128 KiB | 16 KiB | 512 B | 4 B (`JMP`) | `PLANNED` |
| **AVR128DB48** | AVR | AVR-Dx | AVRxt | `avr8:LE:24:xmega` | 128 KiB | 16 KiB | 512 B | 4 B (`JMP`) | `PLANNED` |
| **AVR64DA32** | AVR | AVR-Dx | AVRxt | `avr8:LE:24:xmega` | 64 KiB | 8 KiB | 512 B | 4 B (`JMP`) | `PLANNED` |
| **AVR32DA28** | AVR | AVR-Dx | AVRxt | `avr8:LE:24:xmega` | 32 KiB | 4 KiB | 512 B | 4 B (`JMP`) | `PLANNED` |
| **AVR128DD48** | AVR | AVR-Dx | AVRxt | `avr8:LE:24:xmega` | 128 KiB | 16 KiB | 512 B | 4 B (`JMP`) | `PLANNED` |
| **SAMD21G18A** | SAM | SAMD | ARM Cortex-M0+ | `ARM:LE:32:v6M` | 256 KiB | 32 KiB | None | 4 B (`THUMB`) | `PLANNED` |
| **SAMD21E18A** | SAM | SAMD | ARM Cortex-M0+ | `ARM:LE:32:v6M` | 256 KiB | 32 KiB | None | 4 B (`THUMB`) | `PLANNED` |
| **SAMD51J19A** | SAM | SAMD | ARM Cortex-M4F | `ARM:LE:32:v7EM` | 512 KiB | 192 KiB | None | 4 B (`THUMB`) | `PLANNED` |
| **SAML21J18B** | SAM | SAMD | ARM Cortex-M0+ | `ARM:LE:32:v6M` | 256 KiB | 32 KiB | None | 4 B (`THUMB`) | `PLANNED` |
| **SAMC21J18A** | SAM | SAMD | ARM Cortex-M0+ | `ARM:LE:32:v6M` | 256 KiB | 32 KiB | None | 4 B (`THUMB`) | `PLANNED` |
| **SAME70Q21** | SAM | SAME | ARM Cortex-M7 | `ARM:LE:32:v7EM` | 2048 KiB | 384 KiB | None | 4 B (`THUMB`) | `PLANNED` |
| **SAMS70N21** | SAM | SAME | ARM Cortex-M7 | `ARM:LE:32:v7EM` | 2048 KiB | 384 KiB | None | 4 B (`THUMB`) | `PLANNED` |
| **SAMV71Q21** | SAM | SAME | ARM Cortex-M7 | `ARM:LE:32:v7EM` | 2048 KiB | 384 KiB | None | 4 B (`THUMB`) | `PLANNED` |
| **SAM3X8E** | SAM | SAME | ARM Cortex-M3 | `ARM:LE:32:v7M` | 512 KiB | 96 KiB | None | 4 B (`THUMB`) | `PLANNED` |

---

## 8. Ghidra Language Binding Requirements

The Ghidra SLEIGH language specifications required for each architecture:

1. **`avr8:LE:16:default`**:
   - 16-bit word-addressed code space, 16-bit data address space.
   - Covers classic ATmega and ATtiny parts with Flash $\le$ 64 KiB (`ATmega328P`, `ATtiny85`, etc.).
2. **`avr8:LE:24:default`**:
   - 24-bit word-addressed code space, 16-bit or 24-bit data address space.
   - Covers ATmega devices with Flash > 64 KiB requiring `ELPM` and 3-byte return addresses (`ATmega2560`, `ATmega128`).
3. **`avr8:LE:24:xmega`**:
   - Modern AVRxt core featuring unified linear address mapping, extended instruction sets, and VPORTs (`AVR128DA48`, `ATtiny1614`).
4. **`ARM:LE:32:v6M`**:
   - ARMv6-M Thumb-2 architecture (`SAMD21`, `SAML21`, `SAMC21`).
5. **`ARM:LE:32:v7EM`**:
   - ARMv7E-M architecture with DSP and FPU extensions (`SAME70`, `SAMS70`, `SAMV71`, `SAMD51`).
6. **`ARM:LE:32:v7M`**:
   - ARMv7-M architecture (`SAM3X8E`).

---

## 9. Security, Cryptographic Engines & Documented Unknowns

1. **Hardware Cryptographic Accelerators**:
   - `SAMD51`: Public Key Cryptography Controller (PUKCC), Integrity Check Monitor (ICM), True Random Number Generator (TRNG).
   - `SAME70 / SAMV71`: AES-256 hardware engine, TRNG, ICM.
   - `SAML21`: AES-128 engine, TRNG.
   - `AVR-Dx`: Cyclic Redundancy Check (CRC16/CRC32) scan engine.
2. **Device Locking & Security Bits**:
   - Classic AVR: Lock bits protect Flash and EEPROM from programming and verification.
   - SAM devices: `SECURITY_BIT` disables SWD/JTAG test access. Unlocking requires a full chip erase via debugger pin commands.
3. **Documented Unknowns**:
   - Factory calibration row undocumented trim bits are preserved as opaque vendor configuration blocks without synthetic fabrication.
