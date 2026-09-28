// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>

volatile uint32_t embedra_counter = 0x82660001u;

__attribute__((section(".irom0.text"), noinline))
static uint32_t flash_helper(uint32_t value) {
    return (value ^ 0x13579bdfu) + 7u;
}

__attribute__((section(".text.entry"), noreturn))
void _start(void) {
    embedra_counter = flash_helper(embedra_counter);
    for (;;) {
        __asm__ volatile ("nop");
    }
}
