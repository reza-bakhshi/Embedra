.syntax unified
.thumb

.section .isr_vector,"a",%progbits
.word STACK_TOP
.word Reset_Handler
.rept 14
.word Default_Handler
.endr

.section .text.Reset_Handler,"ax",%progbits
.global Reset_Handler
.thumb_func
Reset_Handler:
    movs r0, #42
1:  b 1b

.section .text.Default_Handler,"ax",%progbits
.global Default_Handler
.thumb_func
Default_Handler:
2:  b 2b

.section .rodata.part,"a",%progbits
.global embedra_fixture_part
embedra_fixture_part:
    .asciz PART_STRING
