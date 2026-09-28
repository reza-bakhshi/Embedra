/* SPDX-License-Identifier: Apache-2.0 */
ENTRY(_start)

MEMORY
{
    dram (rw) : ORIGIN = 0x3ffe8000, LENGTH = 0x18000
    iram (rx) : ORIGIN = 0x40100000, LENGTH = 0x8000
    irom (rx) : ORIGIN = 0x40201010, LENGTH = 0xdf000
}

SECTIONS
{
    .text : { *(.text.entry) *(.text .text.*) } > iram
    .rodata : { *(.rodata .rodata.*) } > dram
    .data : { *(.data .data.*) } > dram
    .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } > dram
    .irom0.text : { *(.irom0.text) } > irom
}
