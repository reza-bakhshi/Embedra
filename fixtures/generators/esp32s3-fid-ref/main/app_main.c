/*
 * SPDX-FileCopyrightText: 2026 Embedra contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Embedra T026A ESP32-S3 Function ID reference application. Original code.
 * It calls a bounded set of stable ESP-IDF v6.0 APIs (esp_timer, esp_log,
 * esp_reset_reason) so the symbolized reference ELF contains real ESP-IDF
 * component functions, and the matching stripped application image can name
 * them through the explicit Embedra Function ID path.
 */
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "embedra_fid_ref";

uint32_t embedra_fid_checksum(const uint8_t *data, uint32_t length)
{
    uint32_t sum = 0x811C9DC5u;
    for (uint32_t i = 0; i < length; i++) {
        sum ^= data[i];
        sum *= 0x01000193u;
    }
    return sum;
}

void app_main(void)
{
    static const char identity[] = "Embedra ESP32-S3 Function ID reference";
    uint64_t started = esp_timer_get_time();
    uint32_t checksum = embedra_fid_checksum((const uint8_t *)identity,
        sizeof(identity));
    ESP_LOGI(TAG, "reset reason: %d", (int)esp_reset_reason());
    ESP_LOGI(TAG, "fid checksum: %08x at %llu us", (unsigned)checksum,
        (unsigned long long)(esp_timer_get_time() - started));
    fflush(stdout);
}
