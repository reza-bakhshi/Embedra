.attribute arch, "rv32imac"
.option arch, +zicsr

/* RP2350 Image Definition Block at 0x10000000 */
.section .image_def, "a"
.global rp2350_image_def_riscv
rp2350_image_def_riscv:
    .word 0xffffded3          /* IMAGE_DEF_START marker */
    .word 0x00000242          /* Item 1: IMAGE_TYPE (Hazard3 RISC-V) */
    .word 0x00000043          /* Item 2: ENTRY tag */
    .word _start              /* Entry pointer */
    .word 0xab123579          /* IMAGE_DEF_END marker */

    /* Pad image_def section to 256 bytes */
    . = rp2350_image_def_riscv + 256

.section .text, "ax"
.global _start
_start:
    /* Set stack pointer to top of 520KB SRAM (0x20082000) */
    lui sp, 0x20082

    /* Configure machine trap vector */
    la t0, trap_handler
    csrw mtvec, t0

    /* RP2350 SIO FIFO interaction (0xD0000050 is FIFO read, 0xD0000054 is FIFO write) */
    lui t1, 0xd0000
    addi t1, t1, 0x54
    li t2, 0x55
    sw t2, 0(t1)

    /* PIO0 Configuration via Hazard3 */
    lui t3, 0x50200
    li t4, 0x01
    sw t4, 0x48(t3)

1:
    wfi
    j 1b

.global trap_handler
.align 4
trap_handler:
    /* Read trap cause and return address */
    csrr t0, mcause
    csrr t1, mepc
    /* Advance return address past trapping instruction if synchronous exception */
    addi t1, t1, 4
    csrw mepc, t1
    mret

.section .rodata, "a"
.global fixture_metadata_rp2350_riscv
fixture_metadata_rp2350_riscv:
    .asciz "RP2350 Hazard3 RISC-V Firmware with Machine Trap Handling and PIO"
