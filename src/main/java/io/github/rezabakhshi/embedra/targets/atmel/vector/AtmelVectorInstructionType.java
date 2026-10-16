package io.github.rezabakhshi.embedra.targets.atmel.vector;

/**
 * Instruction or entry encoding type for Atmel / Microchip vector tables.
 */
public enum AtmelVectorInstructionType {
    /** 2-byte relative jump (RJMP) used on AVR parts with flash &lt;= 8 KiB. */
    RJMP,

    /** 4-byte absolute jump (JMP) used on AVR parts with flash &gt; 8 KiB. */
    JMP,

    /** 32-bit little-endian ARM Cortex-M exception/interrupt handler pointer with Thumb bit. */
    THUMB_VECTOR,

    /** 32-bit initial stack pointer (MSP) at Cortex-M vector table offset 0. */
    INITIAL_SP,

    /** Invalid or corrupted vector entry. */
    INVALID
}
