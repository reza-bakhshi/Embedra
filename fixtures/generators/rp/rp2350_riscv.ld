ENTRY(_start)

MEMORY {
    FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 4096K
    RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 520K
}

SECTIONS {
    .image_def 0x10000000 : {
        KEEP(*(.image_def))
    } > FLASH

    .text 0x10000100 : {
        *(.text*)
        *(.rodata*)
    } > FLASH

    /DISCARD/ : {
        *(.comment*)
        *(.note*)
        *(.riscv.attributes*)
    }
}
