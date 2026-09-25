# ADR 0024: ESP32-C3 as the first RISC-V ESP provider

## Status

Accepted on 2026-09-25.

## Context

The shared ESP contracts were designed to support more than Xtensa, but the
first three implemented providers all selected Xtensa languages. ESP32-C3 chip
ID 5 provides the first concrete test of the ISA boundary. esptool also emits
an address-zero alignment segment before mapped flash code in the independent
C3 fixture, and the pinned Espressif SVD contains some register-name address
conflicts with the pinned ESP-IDF headers.

## Decision

- Resolve chip ID 5 only through the maintained esptool 5.4.0 definition.
- Select Ghidra 12.1.3 `RISCV:LE:32:default` with compiler specification `gcc`
  and two-byte instruction alignment.
- Keep C3 memory ranges and the single RV32IMC application CPU in its provider.
- Checksum-validate esptool alignment segments but omit them from Ghidra memory.
- Keep shared import, mapper, resolver, and entry services free of Xtensa checks.
- Ship independent pinned ROM, peripheral-header, and SVD packs. Where the two
  pinned register sources conflict, record `record-conflicts-prefer-svd`; retain
  the ESP-IDF pack independently and prefer SVD addresses for SVD annotations.

## Consequences

Raw and explicitly enriched C3 application images now import through the same
workflow as the Xtensa targets while selecting a real RISC-V Ghidra language.
This evidence does not cover C3 full-flash layouts, exact silicon variants,
ULP firmware, bootability, or hardware behavior.
