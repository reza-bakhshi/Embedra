# STM8 8-Bit MCU Family Layout, Vector & Architectural Audit

This document records the official technical audit, capability matrix, and
architectural catalog specification for the STMicroelectronics STM8 8-bit
microcontroller family in the Embedra project, covering STM8S, STM8L, STM8A
(STM8AF / STM8AL), and STM8T families against pinned ST reference manuals,
datasheets, Standard Peripheral Library (SPL) headers, and license terms.
It establishes the linear 24-bit memory layout, 32-slot interrupt vector table
architecture anchored at `0x008000`, an allowlist of 32 exact orderable silicon
parts initialized to `PLANNED`, Ghidra language binding requirements, and
strict architectural segregation from 32-bit Cortex-M STM32 targets in
accordance with `Embedra-SpecKit.md` (STM8-001 through STM8-010, Section 8.2A,
and Section 12).

## 1. Scope and Pinned Authoritative Baselines

The STM8 architecture is a dedicated 8-bit CISC microcontroller core produced
by STMicroelectronics. It is entirely distinct from the 32-bit ARM Cortex-M
STM32 product line.

Authoritative documentation and pinned reference baselines:
1. **ST RM0016 Rev 15 (DocID14587)**:
   *STM8S series and STM8AF series 8-bit microcontrollers reference manual*.
   Defines CPU core, memory maps, clock control, power management, option bytes,
   interrupt controller (ITC), and peripherals (TIM1, TIM2, TIM3, TIM4, UART1,
   UART2, UART3, UART4, SPI, I2C, ADC1, ADC2, CAN) for STM8S Value line, Access
   line, Performance line, and STM8AF automotive microcontrollers.
2. **ST RM0031 Rev 15 (DocID15962)**:
   *STM8L05xx, STM8L15xx, STM8L162x, and STM8AL31xx/3Lxx microcontrollers reference manual*.
   Defines ultra-low-power memory architecture, DMA controller, RTC, LCD driver,
   AES hardware accelerator, DAC, ADC, and low-power run/wait/halt modes.
3. **ST PM0044 / RM0013 Rev 5 (DocID13590)**:
   *STM8 CPU programming manual*.
   Authoritative specification of the 8-bit accumulator-based CPU architecture,
   linear 24-bit addressing, condition code register (CC), index registers (X, Y),
   stack pointer (SP), program counter (PC), instruction encodings, and addressing
   modes.
4. **ST STM8 Datasheets**:
   - STM8S: DocID14771 (STM8S003F3/K3), DocID14582 (STM8S103F3/K3), DocID14773
     (STM8S005C6/K6), DocID14733 (STM8S105x4/x6), DocID14776 (STM8S007C8),
     DocID14732 (STM8S207xx), DocID14734 (STM8S208xx).
   - STM8L: DocID022474 (STM8L051F3), DocID022475 (STM8L052R8), DocID14318
     (STM8L151x4/x6), DocID15460 (STM8L151x6/x8), DocID15093 (STM8L152x6/x8),
     DocID022137 (STM8L162R8).
   - STM8A: DocID14399 (STM8AF52xx/62xx), DocID022476 (STM8AL31xx/3Lxx).
   - STM8T: DocID15655 (STM8T141), DocID15656 (STM8T143).
5. **ST Standard Peripheral Library (SPL) Headers**:
   - `stm8s.h` from STM8S/A Standard Peripherals Library v2.3.1.
   - `stm8l15x.h` from STM8L/AL Standard Peripherals Library v1.6.2.

## 2. ST Documentation Provenance & License Analysis

In accordance with CORE-013, STM8-007, and the repository license policy:
1. **Datasheets & Reference Manuals**:
   - Copyright (C) STMicroelectronics. Technical facts, register offsets, memory
     boundaries, and instruction opcodes extracted from published reference
     manuals constitute non-copyrightable factual data under applicable
     jurisdictions.
2. **Standard Peripheral Library (SPL) Headers**:
   - Licensed under the ST MCD-ST Liberty license v2 / ST permissive terms
     permitting redistribution, modification, and use in binary or source forms
     without requiring reciprocal source disclosure (no GPL/copyleft infection).
   - Redistribution of derived register data packs (planned for T092) preserves
     ST copyright notices and attribution in compliance with `THIRD_PARTY_NOTICES.md`.
3. **Compiler Toolchains & Runtimes**:
   - SDCC (Small Device C Compiler): GPL runtime exception allows linking open-source
     runtime routines into proprietary or permissive targets.
   - Cosmic and IAR STM8 toolchains: proprietary commercial compilers; signatures
     for compiler intrinsics remain heuristic and attribution-safe.

## 3. CPU Core Architecture & Execution Model

The STM8 CPU core is an 8-bit CISC Harvard architecture featuring:
- **Accumulator (`A`)**: 8-bit register for arithmetic, logical, and data transfer
  operations.
- **Index Registers (`X` and `Y`)**: Two symmetrical 16-bit registers used for
  indirect addressing, memory pointers, 16-bit arithmetic, and indexing with
  8-bit or 16-bit offsets.
- **Stack Pointer (`SP`)**: 16-bit register pointing to the next available stack
  slot in internal SRAM. The stack grows downwards. In devices with <= 2 KiB RAM,
  the hardware upper bits are physically bounded to the device's RAM range.
- **Program Counter (`PC`)**: 24-bit register allowing direct, linear execution
  across the entire 16 MiB address space (`0x000000` to `0xFFFFFF`). In devices
  with <= 128 KiB program Flash, code resides between `0x008000` and `0x027FFF`.
- **Condition Code Register (`CC`)**: 8-bit status register containing:
  - Bit 5 (`V`): Overflow flag
  - Bit 4 (`I1`): Interrupt mask level 1
  - Bit 3 (`H`): Half-carry flag (for BCD operations)
  - Bit 2 (`I0`): Interrupt mask level 0
  - Bit 1 (`N`): Negative flag
  - Bit 0 (`Z`): Zero flag
  - Carry (`C`): Carry flag
- **Endianness**: Multi-byte words, 16-bit pointers, and 24-bit extended addresses
  are stored in memory in **big-endian** order (most significant byte at the lowest
  memory address).
- **Instruction Width**: Variable length (1 to 5 bytes). The opcode `0x82` denotes
  the absolute 24-bit unconditional jump instruction (`JP extended` or `JPF`),
  followed by 3 address bytes (`MSB`, `MID`, `LSB`).

## 4. Unified Linear Memory Map & Invariants

STM8 microcontrollers provide a unified, flat 24-bit memory space where all
memories, configuration bytes, and peripherals are memory-mapped:

| Region | Base Address | Typical End Address | Description |
|---|---|---|---|
| **RAM (Internal SRAM)** | `0x000000` | `0x0001FF` to `0x0017FF` | Internal data SRAM (512 B to 6 KiB). Stack grows downwards from top of RAM. |
| **Reserved / Unmapped** | `RAM_END + 1` | `0x003FFF` | Unmapped memory space; access generates illegal bus response or reads zeros. |
| **Data EEPROM** | `0x004000` | `0x00407F` to `0x0047FF` | Non-volatile data EEPROM (128 B to 2 KiB). Byte-programmable and readable. |
| **Option Bytes** | `0x004800` | `0x00487F` / `0x0048FF` | Device configuration bytes: ROP (readout protection), UBC (user boot code), AFR, WDG. |
| **Reserved / Unmapped** | `0x004900` | `0x004FFF` | Reserved gap between option bytes and peripherals. |
| **Peripheral Registers**| `0x005000` | `0x0057FF` | Hardware MMIO registers (GPIO, Clocks, Timers, UART, SPI, I2C, ADC, CAN). Page 0 accessible. |
| **Reserved / Unmapped** | `0x005800` | `0x005FFF` | Reserved space. |
| **Boot ROM (System Mem)**| `0x006000` | `0x0067FF` | Factory bootloader (2 KiB) implementing serial ISP protocols (UART, SPI, CAN). |
| **Reserved / Unmapped** | `0x006800` | `0x007FFF` | Reserved space preceding Flash. |
| **Program Flash (Code)**| `0x008000` | `0x008FFF` to `0x027FFF` | Non-volatile Flash memory (4 KiB to 128 KiB). Contains vector table at base `0x008000`. |

Invariants enforced across all STM8 target providers:
1. `FLASH_BASE` is invariant at `0x008000`. Program flash never starts at `0x000000`.
2. `RAM_BASE` is invariant at `0x000000`.
3. `EEPROM_BASE` is invariant at `0x004000`.
4. `OPTION_BYTES_BASE` is invariant at `0x004800`.
5. `PERIPHERALS_BASE` is invariant at `0x005000` and spans to `0x0057FF`.
6. `BOOT_ROM_BASE` is invariant at `0x006000` and spans 2 KiB (`0x0067FF`).
7. Memory regions are strictly contiguous within their declared physical bounds
   and MUST NOT overlap.

## 5. Interrupt Vector Table Architecture

The STM8 interrupt vector table is located at the very base of physical Flash
memory (`0x008000`):

- **Vector Count**: 32 vector slots (Slots 0 to 31).
- **Entry Size**: Exactly 4 bytes per slot.
- **Table Size**: 128 bytes (`0x008000` to `0x00807F`).
- **Entry Format**:
  - Byte 0: Opcode `0x82` (`JP` absolute 24-bit).
  - Byte 1: Target address bits 23..16 (high byte).
  - Byte 2: Target address bits 15..8 (middle byte).
  - Byte 3: Target address bits 7..0 (low byte).
- **Target Validity**: The 24-bit jump target MUST point to a valid address within
  the part's physical program Flash range (`0x008000` to `0x008000 + FLASH_SIZE - 1`)
  or the factory boot ROM range (`0x006000` to `0x0067FF`).

### 5.1 Universal Vector Slots (Slots 0 to 9)

All STM8 families share the first 10 interrupt vector slots:
- **Slot 0 (`0x008000`)**: Reset Vector (Entry point on hardware power-on / reset)
- **Slot 1 (`0x008004`)**: TRAP (Non-maskable software interrupt)
- **Slot 2 (`0x008008`)**: TLI (Top Level Interrupt external pin)
- **Slot 3 (`0x00800C`)**: AWU (Auto Wake Up from halt mode)
- **Slot 4 (`0x008010`)**: CLK (Clock Controller / CSS Clock Security System)
- **Slot 5 (`0x008014`)**: EXTI0 (Port A external interrupt)
- **Slot 6 (`0x008018`)**: EXTI1 (Port B external interrupt)
- **Slot 7 (`0x00801C`)**: EXTI2 (Port C external interrupt)
- **Slot 8 (`0x008020`)**: EXTI3 (Port D external interrupt)
- **Slot 9 (`0x008024`)**: EXTI4 (Port E external interrupt)

### 5.2 Family-Specific Peripheral Slots (Slots 10 to 31)

- **STM8S & STM8AF (RM0016)**:
  - Slot 10 (`0x008028`): CAN RX (STM8S208/AF52) / Reserved
  - Slot 11 (`0x00802C`): CAN TX / Error (STM8S208/AF52) / Reserved
  - Slot 12 (`0x008030`): SPI end of transfer
  - Slot 13 (`0x008034`): TIM1 Update / Overflow / Trigger / Break
  - Slot 14 (`0x008038`): TIM1 Capture / Compare
  - Slot 15 (`0x00803C`): TIM2 Update / Overflow
  - Slot 16 (`0x008040`): TIM2 Capture / Compare
  - Slot 17 (`0x008044`): TIM3 Update / Overflow
  - Slot 18 (`0x008048`): TIM3 Capture / Compare
  - Slot 19 (`0x00804C`): UART1 TX complete / UART4 TX complete
  - Slot 20 (`0x008050`): UART1 RX full / UART4 RX full
  - Slot 21 (`0x008054`): I2C event / error
  - Slot 22 (`0x008058`): UART2/UART3 TX complete
  - Slot 23 (`0x00805C`): UART2/UART3 RX full
  - Slot 24 (`0x008060`): ADC1 / ADC2 end of conversion
  - Slot 25 (`0x008064`): TIM4 Update / Overflow
  - Slot 26 (`0x008068`): Flash EOP (End of Programming)
  - Slots 27–31 (`0x00806C` - `0x00807C`): Reserved

- **STM8L & STM8AL (RM0031)**:
  - Slot 10 (`0x008028`): Flash EOP / AES end of execution
  - Slot 11 (`0x00802C`): DMA1 Channels 0 & 1
  - Slot 12 (`0x008030`): DMA1 Channels 2 & 3
  - Slot 13 (`0x008034`): RTC / CSS_LSE
  - Slot 14 (`0x008038`): EXTIE_F / PVD
  - Slot 15 (`0x00803C`): EXTIB / EXTIG
  - Slot 16 (`0x008040`): EXTID / EXTIE
  - Slot 17 (`0x008044`): USART1 TX
  - Slot 18 (`0x008048`): USART1 RX
  - Slot 19 (`0x00804C`): I2C1 / SPI1
  - Slot 20 (`0x008050`): TIM1 Update / Trigger
  - Slot 21 (`0x008054`): TIM1 Capture / Compare
  - Slot 22 (`0x008058`): TIM2 Update / Trigger
  - Slot 23 (`0x00805C`): TIM2 Capture / Compare
  - Slot 24 (`0x008060`): TIM3 Update / Trigger
  - Slot 25 (`0x008064`): TIM3 Capture / Compare
  - Slot 26 (`0x008068`): USART2/3 TX
  - Slot 27 (`0x00806C`): USART2/3 RX
  - Slot 28 (`0x008070`): ADC1 / COMP
  - Slot 29 (`0x008074`): LCD driver
  - Slot 30 (`0x008078`): TIM4 Update
  - Slot 31 (`0x00807C`): SPI2 / USART3 / Reserved

- **STM8T (Touch Sensing)**:
  - Slot 10 (`0x008028`): ProxSense touch acquisition complete
  - Slot 11 (`0x00802C`): ProxSense error / threshold
  - Slots 12–25: SPI, I2C, UART, TIM2, TIM4, ADC.

## 6. Curated Exact-Part Allowlist (32 Silicon Parts)

Embedra curates 32 exact orderable silicon parts across all four lines:
STM8S (14), STM8L (8), STM8A (7), and STM8T (3). All records initialize in the
`PLANNED` support state per STM8-010.

### 6.1 STM8S Mainstream Line (14 Parts)

| Part Number | Package | Flash | RAM | EEPROM | Timers | Comms | Analog | Other | Status |
|---|---|---|---|---|---|---|---|---|---|
| `STM8S003F3P6` | TSSOP20 | 8 KiB | 1 KiB | 128 B | TIM1, TIM2, TIM4 | UART1, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S003K3T6C`| LQFP32  | 8 KiB | 1 KiB | 128 B | TIM1, TIM2, TIM4 | UART1, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S103F3P6` | TSSOP20 | 8 KiB | 1 KiB | 640 B | TIM1, TIM2, TIM4 | UART1, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S103K3T6C`| LQFP32  | 8 KiB | 1 KiB | 640 B | TIM1, TIM2, TIM4 | UART1, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S005K6T6C`| LQFP32  | 32 KiB| 2 KiB | 128 B | TIM1, TIM2, TIM3, TIM4 | UART2, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S005C6T6` | LQFP48  | 32 KiB| 2 KiB | 128 B | TIM1, TIM2, TIM3, TIM4 | UART2, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S105K4T6C`| LQFP32  | 16 KiB| 2 KiB | 1 KiB | TIM1, TIM2, TIM3, TIM4 | UART2, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S105K6T6C`| LQFP32  | 32 KiB| 2 KiB | 1 KiB | TIM1, TIM2, TIM3, TIM4 | UART2, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S105C6T6` | LQFP48  | 32 KiB| 2 KiB | 1 KiB | TIM1, TIM2, TIM3, TIM4 | UART2, SPI, I2C | 10-bit ADC1 | WWDG, IWDG | `PLANNED` |
| `STM8S007C8T6` | LQFP48  | 64 KiB| 6 KiB | 128 B | TIM1, TIM2, TIM3, TIM4 | UART1, UART3, SPI, I2C | 10-bit ADC2 | WWDG, IWDG | `PLANNED` |
| `STM8S207C8T6` | LQFP48  | 64 KiB| 6 KiB | 1.5 KiB| TIM1, TIM2, TIM3, TIM4| UART1, UART3, SPI, I2C | 10-bit ADC2 | WWDG, IWDG | `PLANNED` |
| `STM8S207RBT6` | LQFP64  | 128 KiB|6 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | UART1, UART3, SPI, I2C | 10-bit ADC2 | WWDG, IWDG | `PLANNED` |
| `STM8S208RBT6` | LQFP64  | 128 KiB|6 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | UART1, UART3, SPI, I2C, CAN | 10-bit ADC2 | beeper, WWDG | `PLANNED` |
| `STM8S208MBT6B`| LQFP80  | 128 KiB|6 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | UART1, UART3, SPI, I2C, CAN | 10-bit ADC2 | beeper, WWDG | `PLANNED` |

### 6.2 STM8L Ultra-Low-Power Line (8 Parts)

| Part Number | Package | Flash | RAM | EEPROM | Timers | Comms | Analog | Other | Status |
|---|---|---|---|---|---|---|---|---|---|
| `STM8L051F3P6` | TSSOP20 | 8 KiB | 1 KiB | 256 B | TIM2, TIM3, TIM4 | USART1, SPI1, I2C1 | 12-bit ADC1 | RTC, DMA | `PLANNED` |
| `STM8L052R8T6` | LQFP64  | 64 KiB| 4 KiB | 256 B | TIM1, TIM2, TIM3, TIM4 | USART1, USART2, USART3, SPI1, SPI2, I2C1 | 12-bit ADC1, DAC | LCD driver, RTC, DMA | `PLANNED` |
| `STM8L151K4T6` | LQFP32  | 16 KiB| 2 KiB | 1 KiB | TIM2, TIM3, TIM4 | USART1, SPI1, I2C1 | 12-bit ADC1 | RTC, DMA | `PLANNED` |
| `STM8L151G6U6` | UFQFPN28| 32 KiB| 2 KiB | 1 KiB | TIM2, TIM3, TIM4 | USART1, SPI1, I2C1 | 12-bit ADC1 | RTC, DMA | `PLANNED` |
| `STM8L151C8T6` | LQFP48  | 64 KiB| 4 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | USART1, USART2, SPI1, I2C1 | 12-bit ADC1, DAC | RTC, DMA | `PLANNED` |
| `STM8L152C6T6` | LQFP48  | 32 KiB| 2 KiB | 1 KiB | TIM1, TIM2, TIM3, TIM4 | USART1, SPI1, I2C1 | 12-bit ADC1, DAC | LCD driver, RTC, DMA | `PLANNED` |
| `STM8L152R8T6` | LQFP64  | 64 KiB| 4 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | USART1, USART2, USART3, SPI1, SPI2, I2C1 | 12-bit ADC1, DAC | LCD driver, RTC, DMA | `PLANNED` |
| `STM8L162R8T6` | LQFP64  | 64 KiB| 4 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | USART1, USART2, USART3, SPI1, SPI2, I2C1 | 12-bit ADC1, DAC | AES accelerator, LCD, RTC, DMA | `PLANNED` |

### 6.3 STM8A Automotive Line (7 Parts)

| Part Number | Family | Package | Flash | RAM | EEPROM | Timers | Comms | Other | Status |
|---|---|---|---|---|---|---|---|---|---|
| `STM8AF6226ITAY`| STM8AF | TSSOP20 | 8 KiB  | 1 KiB | 640 B | TIM1, TIM2, TIM4 | LIN-UART, SPI, I2C | 10-bit ADC1, AEC-Q100 | `PLANNED` |
| `STM8AF6266TAY` | STM8AF | LQFP32  | 32 KiB | 2 KiB | 1 KiB | TIM1, TIM2, TIM3, TIM4 | LIN-UART, SPI, I2C | 10-bit ADC1, AEC-Q100 | `PLANNED` |
| `STM8AF6288TAY` | STM8AF | LQFP48  | 64 KiB | 6 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | LIN-UART, UART3, SPI, I2C | 10-bit ADC2, AEC-Q100 | `PLANNED` |
| `STM8AF5288TAY` | STM8AF | LQFP48  | 64 KiB | 6 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | CAN 2.0B, LIN-UART, UART3, SPI, I2C | 10-bit ADC2, AEC-Q100 | `PLANNED` |
| `STM8AL3166TA`  | STM8AL | LQFP32  | 32 KiB | 2 KiB | 1 KiB | TIM2, TIM3, TIM4 | LIN-USART, SPI1, I2C1 | 12-bit ADC1, Low power | `PLANNED` |
| `STM8AL3188TA`  | STM8AL | LQFP48  | 64 KiB | 4 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | LIN-USART, USART2, SPI1, I2C1 | 12-bit ADC1, DAC, Low power | `PLANNED` |
| `STM8AL3L88TA`  | STM8AL | LQFP48  | 64 KiB | 4 KiB | 2 KiB | TIM1, TIM2, TIM3, TIM4 | LIN-USART, USART2, SPI1, I2C1 | LCD driver, 12-bit ADC1, DAC | `PLANNED` |

### 6.4 STM8T Touch-Sensing Line (3 Parts)

| Part Number | Package | Flash | RAM | EEPROM | Timers | Comms | Touch Controller | Status |
|---|---|---|---|---|---|---|---|---|
| `STM8T141AM` | SO8     | 4 KiB | 512 B | 128 B | TIM2, TIM4 | I2C, SPI, UART | ProxSense 1-channel touch | `PLANNED` |
| `STM8T143AU` | UFQFPN20| 8 KiB | 1 KiB | 128 B | TIM2, TIM3, TIM4 | I2C, SPI, UART | ProxSense 8-channel touch | `PLANNED` |
| `STM8T143AM` | SO20    | 8 KiB | 1 KiB | 128 B | TIM2, TIM3, TIM4 | I2C, SPI, UART | ProxSense 8-channel touch | `PLANNED` |

## 7. Ghidra Language Binding Specification

In accordance with STM8-006:
1. **Target Processor**: `STM8`.
2. **Language IDs**:
   - `STM8:default:16:default` (16-bit address space for smaller microcontrollers).
   - `STM8:default:24:default` (24-bit linear address space for full memory maps).
3. **Upstream Ghidra Distribution Status**:
   - Standard Ghidra 12.1.3 PUBLIC distributions do not bundle a built-in STM8
     SLEIGH processor module under `Ghidra/Processors/STM8/`.
4. **Fail-Closed Diagnostic Protocol**:
   - Embedra will query Ghidra's `DefaultLanguageService` upon STM8 part or
     format detection.
   - If no compatible STM8 language definition is found in the running Ghidra
     installation, the import process MUST abort immediately with a stable,
     descriptive error message:
     `"Required Ghidra language 'STM8:default:16:default' or 'STM8:default:24:default' is not installed in the host Ghidra distribution."`
   - No partial or corrupted program state may be committed to the project.

## 8. Strict Segregation from STM32 Architecture

In accordance with STM8-001 and ADR 0025:
1. **Core Architecture**:
   - STM8 is an 8-bit CISC processor with big-endian byte order, an accumulator,
     and 16-bit index registers.
   - STM32 is a 32-bit ARM Cortex-M processor with little-endian byte order,
     Thumb-2 instruction set, and general-purpose registers R0–R15.
2. **Vector Table Semantics**:
   - STM8 vectors start at `0x008000` with 4-byte entries containing opcode
     `0x82` followed by a 24-bit big-endian target address.
   - STM32 vectors start at `0x00000000` (or `0x08000000` / VTOR) with a 32-bit
     Initial Stack Pointer followed by 32-bit little-endian handler addresses with
     bit 0 set (Thumb bit).
3. **Peripheral Subsystems & SVD**:
   - STM8 peripherals reside in page 0 (`0x005000` to `0x0057FF`) with 8-bit
     register widths and 1-byte alignments.
   - STM32 peripherals reside in 32-bit memory space (`0x40000000`+) with 32-bit
     word alignments.
   - CMSIS-SVD packages, CMSIS device headers, and STM32Cube libraries MUST NEVER
     be applied to STM8 targets.
4. **Codebase Isolation**:
   - Target providers, catalog descriptors, vector table decoders, and memory
     planners for STM8 will reside strictly under `io.github.rezabakhshi.embedra.targets.stm8`
     and `io.github.rezabakhshi.embedra.formats.stm8`.

## 9. Unknowns, Documentation Gaps & Preliminary Notes

1. **Ghidra Host SLEIGH Availability**:
   - Because Ghidra does not ship an official in-tree STM8 module, test suites
     validating STM8 providers in headless Ghidra must supply an isolated,
     redistributable mock or test SLEIGH module or verify language-service
     fallbacks cleanly.
2. **STM8T Factory Bootloader Specifications**:
   - Boot ROM protocols on STM8T touch microcontrollers are partially documented
     compared to the comprehensive UART/CAN bootloader documentation in RM0016
     for STM8S/AF. Embedra records factory boot ROM as `0x006000`–`0x0067FF`
     with `UNCONFIRMED_PROTOCOL` attribution.
3. **Option Byte Inversion**:
   - STM8 hardware requires option bytes to be stored in pairs: each option byte
     is followed by its bitwise complement (`OPTx` and `NOPTx`). Embedra's
     option-byte models must validate the complement checksum to verify option
     byte integrity.
