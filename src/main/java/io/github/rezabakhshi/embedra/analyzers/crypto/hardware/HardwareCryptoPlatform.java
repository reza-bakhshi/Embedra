package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

/**
 * Target device hardware family for hardware crypto peripherals and ROM routines (AN-013).
 */
public enum HardwareCryptoPlatform {
    ESP32("Espressif ESP32", "esp32"),
    ESP32_S2("Espressif ESP32-S2", "esp32s2"),
    ESP32_S3("Espressif ESP32-S3", "esp32s3"),
    ESP32_C3("Espressif ESP32-C3", "esp32c3"),
    ESP32_C6("Espressif ESP32-C6", "esp32c6"),
    ESP32_H2("Espressif ESP32-H2", "esp32h2"),
    STM32_F4("STMicroelectronics STM32F4", "stm32f4"),
    STM32_F7("STMicroelectronics STM32F7", "stm32f7"),
    STM32_H7("STMicroelectronics STM32H7", "stm32h7"),
    STM32_L4("STMicroelectronics STM32L4", "stm32l4"),
    STM32_L5("STMicroelectronics STM32L5", "stm32l5"),
    STM32_U5("STMicroelectronics STM32U5", "stm32u5"),
    STM32_WB("STMicroelectronics STM32WB", "stm32wb"),
    RP2040("Raspberry Pi RP2040", "rp2040"),
    RP2350("Raspberry Pi RP2350", "rp2350"),
    GENERIC("Generic / Vendor Independent", "generic");

    private final String displayName;

    private final String platformKey;

    HardwareCryptoPlatform(String displayName, String platformKey) {
        this.displayName = displayName;
        this.platformKey = platformKey;
    }

    public String displayName() {
        return displayName;
    }

    public String platformKey() {
        return platformKey;
    }

    public static HardwareCryptoPlatform fromKey(String key) {
        if (key == null || key.isBlank()) {
            return GENERIC;
        }
        String lower = key.trim().toLowerCase(java.util.Locale.ROOT);
        for (HardwareCryptoPlatform p : values()) {
            if (p.platformKey.equals(lower) || lower.contains(p.platformKey)) {
                return p;
            }
        }
        return GENERIC;
    }
}
