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
    .rodata 0x3f400020 :
    {
        KEEP(*(.rodata_desc))
        *(.rodata*)
    } :rodata

    .text 0x40080000 :
    {
        *(.literal*)
        *(.text.entry)
        *(.text*)
    } :text

    .data 0x3ffae000 :
    {
        *(.data*)
    } :data

    .bss (NOLOAD) :
    {
        *(.bss*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.note*)
        *(.eh_frame*)
    }
}
