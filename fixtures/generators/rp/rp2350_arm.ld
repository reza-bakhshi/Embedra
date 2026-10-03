ENTRY(Reset_Handler_TZ)

MEMORY {
    FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 4096K
    RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 520K
}

SECTIONS {
    .image_def 0x10000000 : {
        KEEP(*(.image_def))
    } > FLASH

    .isr_vector 0x10000100 : {
        KEEP(*(.isr_vector))
    } > FLASH

    .text : {
        *(.text*)
        *(.rodata*)
    } > FLASH

    .nsc_entry : {
        *(.nsc_entry*)
    } > FLASH

    /DISCARD/ : {
        *(.comment*)
        *(.note*)
        *(.ARM.attributes*)
    }
}
