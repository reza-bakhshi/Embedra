/*
 * SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
 * SPDX-FileCopyrightText: 2026 Embedra contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The application-description layout is adapted from ESP-IDF v6.0's
 * esp_app_desc.h. The fixture contains no ESP-IDF runtime code.
 */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

typedef struct {
    uint32_t magic_word;
    uint32_t secure_version;
    uint32_t reserved1[2];
    char version[32];
    char project_name[32];
    char time[16];
    char date[16];
    char idf_version[32];
    uint8_t app_elf_sha256[32];
    uint16_t minimum_efuse_block_revision;
    uint16_t maximum_efuse_block_revision;
    uint8_t mmu_page_size_log2;
    uint8_t reserved3[3];
    uint32_t reserved2[18];
} AppDescription;

_Static_assert(sizeof(AppDescription) == 256, "application description size");

__attribute__((section(".rodata_desc"), used))
static const AppDescription embedra_app_description = {
    .magic_word = 0xabcd5432U,
    .secure_version = 0,
    .version = "1.0.0",
    .project_name = "embedra_t008_fixture",
    .idf_version = "fixture-no-idf-runtime",
    .maximum_efuse_block_revision = 199,
    .mmu_page_size_log2 = 16
};

__attribute__((used)) static const char embedra_fixture_identity[] =
    "Embedra ESP32-S3 T008 golden fixture";
static volatile uint32_t embedra_fixture_marker = 0x45385333U;

__attribute__((section(".text.entry"))) void _start(void)
{
    embedra_fixture_marker ^= 0x53335438U;
    for (;;) {
        __asm__ volatile ("waiti 0");
    }
}
