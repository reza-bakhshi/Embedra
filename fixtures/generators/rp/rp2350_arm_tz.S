.syntax unified
.cpu cortex-m33
.thumb

/* RP2350 Image Definition Block at 0x10000000 */
.section .image_def, "a", %progbits
.global rp2350_image_def
rp2350_image_def:
    .word 0xffffded3          /* IMAGE_DEF_START marker */
    .word 0x00000142          /* Item 1: IMAGE_TYPE (ARMv8-M Cortex-M33 Secure) */
    .word 0x00000043          /* Item 2: VECTOR_TABLE tag */
    .word isr_vector_tz       /* Vector table pointer */
    .word 0xab123579          /* IMAGE_DEF_END marker */

    /* Pad image_def section to 256 bytes so vector table starts cleanly at 0x10000100 */
    . = rp2350_image_def + 256

/* Secure Vector Table at 0x10000100 */
.section .isr_vector, "a", %progbits
.global isr_vector_tz
isr_vector_tz:
    .word 0x20082000          /* Initial SP: top of 520KB SRAM */
    .word Reset_Handler_TZ    /* Reset Handler */
    .rept 14
    .word Default_Handler_TZ
    .endr

.section .text, "ax", %progbits
.global Reset_Handler_TZ
.thumb_func
Reset_Handler_TZ:
    /* Configure SAU / Security Boundaries */
    bl configure_sau

    /* RP2350 PIO2 hardware setup (PIO2 is specific to RP2350, base 0x50400000) */
    ldr r0, =0x50400048       /* PIO2 INSTR_MEM0 */
    movs r1, #0x01
    str r1, [r0]

    /* SIO Spinlock 0 acquire test (0xD0000100 is SPINLOCK0) */
    ldr r0, =0xd0000100
    ldr r1, [r0]

    /* Main Secure Loop */
1:
    wfi
    b 1b

.global configure_sau
.thumb_func
configure_sau:
    /* SAU Control Register at 0xE000EDD0 */
    ldr r0, =0xe000edd0
    movs r1, #1               /* Enable SAU */
    str r1, [r0]
    bx lr

.global Default_Handler_TZ
.thumb_func
Default_Handler_TZ:
    b .

/* TrustZone Non-Secure Callable (NSC) Veneer */
.section .nsc_entry, "ax", %progbits
.global nsc_secure_service
.thumb_func
nsc_secure_service:
    /* ARMv8-M Security Gateway instruction (sg) */
    .inst.w 0xe97fe97f        /* SG opcode */
    /* Process secure service */
    movs r0, #0x42
    /* Branch and exchange to non-secure caller */
    bxns lr

.section .rodata, "a", %progbits
.global fixture_metadata_rp2350_arm
fixture_metadata_rp2350_arm:
    .asciz "RP2350 Cortex-M33 TrustZone Secure Firmware with PIO2 and NSC"
