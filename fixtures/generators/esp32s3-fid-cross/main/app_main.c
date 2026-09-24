/*
 * SPDX-FileCopyrightText: 2026 Embedra contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Embedra T026A cross-application ESP32-S3 reference (app-b). Original code.
 * A different main function that still calls the same stable ESP-IDF v6.0 APIs,
 * proving a FIDB built from app-a names shared IDF functions in an unrelated
 * application linked from the same pinned build environment.
 */
#include <string.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"

static const char *TAG = "embedra_fid_cross";

uint32_t embedra_fid_variant(uint32_t seed)
{
    for (int i = 0; i < 12; i++) {
        seed = (seed << 5) | (seed >> 27);
        seed ^= 0x5f356495u + i;
    }
    return seed;
}

void app_main(void)
{
    uint32_t mixed = embedra_fid_variant(0xC0FFEEu);
    ESP_LOGI(TAG, "reason=%d mixed=%08x t=%lld", (int)esp_reset_reason(),
        (unsigned)mixed, (long long)esp_timer_get_time());
}
