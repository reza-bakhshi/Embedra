.syntax unified
.cpu cortex-m0plus
.thumb

/* Boot2 256-byte header at 0x10000000 */
.section .boot2, "ax", %progbits
.global boot2_entry
boot2_entry:
    push {lr}
    /* Jump to main vector table */
    ldr r0, =0x10000100
    ldr r1, [r0, #4] /* Reset handler */
    blx r1
    pop {pc}
    .ltorg
    /* Pad boot2 to exactly 256 bytes (252 data + 4 CRC placeholder) */
    . = boot2_entry + 252
    .word 0x43524332 /* "CRC2" */

/* ISR Vector table at 0x10000100 */
.section .isr_vector, "a", %progbits
.global isr_vector
isr_vector:
    .word 0x20042000          /* Initial SP: top of 264KB SRAM */
    .word Reset_Handler       /* Reset Handler (Thumb mode, bit 0 = 1) */
    .rept 14
    .word Default_Handler
    .endr

.section .text, "ax", %progbits
.global Reset_Handler
.thumb_func
Reset_Handler:
    /* Initialize TinyUSB */
    bl tud_init

    /* Periodic TinyUSB task */
    bl tud_task

    /* Initialize PIO hardware */
    bl rp_pio_init

    /* Launch Core 1 via SIO FIFO (0xD0000054 is FIFO write) */
    ldr r0, =0xd0000054
    ldr r1, =Core1_Entry
    str r1, [r0]

    /* Main Core 0 loop */
1:
    bl tud_task
    wfi
    b 1b

.global Core1_Entry
.thumb_func
Core1_Entry:
    /* Core 1 waits for commands via SIO FIFO (0xD0000050 is FIFO read) */
    ldr r0, =0xd0000050
    ldr r1, [r0]
2:
    wfe
    b 2b

.global Default_Handler
.thumb_func
Default_Handler:
    b .

/* TinyUSB Mock Implementations */
.global tud_init
.thumb_func
tud_init:
    movs r0, #1
    bx lr

.global tud_task
.thumb_func
tud_task:
    bx lr

.global tud_cdc_read
.thumb_func
tud_cdc_read:
    movs r0, #0
    bx lr

.global tud_cdc_write
.thumb_func
tud_cdc_write:
    movs r0, #0
    bx lr

/* PIO Mock Implementation and Instructions */
.global rp_pio_init
.thumb_func
rp_pio_init:
    /* Load PIO instructions into PIO0 instruction memory at 0x50200000 */
    ldr r0, =0x50200048 /* PIO0 INSTR_MEM0 */
    ldr r1, =rp_pio_instructions
    ldrh r2, [r1]
    str r2, [r0]
    bx lr

.section .rodata, "a", %progbits
.global rp_pio_instructions
rp_pio_instructions:
    .short 0xe001 /* SET pins, 1 */
    .short 0xe000 /* SET pins, 0 */
    .short 0x0000 /* JMP 0 */

.global fixture_metadata
fixture_metadata:
    .asciz "RP2040 Freestanding Dual-Core Firmware with TinyUSB and PIO"
