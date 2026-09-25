/* SPDX-License-Identifier: Apache-2.0 */

ENTRY(_start)

PHDRS
{
    rodata PT_LOAD FLAGS(4);
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    .rodata 0x3c000020 :
    {
        KEEP(*(.rodata_desc))
        *(.rodata*)
    } :rodata

    .text 0x42000000 :
    {
        *(.text.entry)
        *(.text*)
    } :text

    .data 0x3fc80000 :
    {
        *(.sdata*)
        *(.data*)
    } :data

    .bss (NOLOAD) :
    {
        *(.sbss*)
        *(.bss*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.note*)
        *(.eh_frame*)
        *(.riscv.attributes)
    }
}
