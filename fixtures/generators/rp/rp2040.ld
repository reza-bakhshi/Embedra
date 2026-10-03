ENTRY(boot2_entry)

MEMORY {
    FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 2048K
    RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 264K
}

SECTIONS {
    .boot2 0x10000000 : {
        KEEP(*(.boot2))
    } > FLASH

    .isr_vector 0x10000100 : {
        KEEP(*(.isr_vector))
    } > FLASH

    .text : {
        *(.text*)
        *(.rodata*)
    } > FLASH

    /DISCARD/ : {
        *(.comment*)
        *(.note*)
        *(.ARM.attributes*)
    }
}
