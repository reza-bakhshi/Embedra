package io.github.rezabakhshi.embedra.formats.esp.layout;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Registry of available ESP flash layout providers.
 */
public final class EspFlashLayoutRegistry {
    private static final EspFlashLayoutRegistry DEFAULT_INSTANCE = new EspFlashLayoutRegistry();

    private final Map<Integer, EspFlashLayoutProvider> byChipId;

    private final Map<String, EspFlashLayoutProvider> bySeries;

    public EspFlashLayoutRegistry() {
        this.byChipId = new LinkedHashMap<>();
        this.bySeries = new LinkedHashMap<>();
        register(Esp32S3FlashLayoutProvider.INSTANCE);
        register(Esp32FlashLayoutProvider.INSTANCE);
        register(Esp32S2FlashLayoutProvider.INSTANCE);
        register(EspRiscVFlashLayoutProvider.of("ESP32-C3", 5, "ESP32-C3", "esptool/targets/esp32c3.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-C2", 12, "ESP32-C2", "esptool/targets/esp32c2.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-C5", 23, "ESP32-C5", "esptool/targets/esp32c5.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-C6", 13, "ESP32-C6", "esptool/targets/esp32c6.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-C61", 20, "ESP32-C61", "esptool/targets/esp32c61.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-H2", 16, "ESP32-H2", "esptool/targets/esp32h2.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-H21", 25, "ESP32-H21", "esptool/targets/esp32h21.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-H4", 28, "ESP32-H4", "esptool/targets/esp32h4.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-P4", 18, "ESP32-P4", "esptool/targets/esp32p4.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-S31", 32, "ESP32-S31", "esptool/targets/esp32s31.py"));
        register(EspRiscVFlashLayoutProvider.of("ESP32-E22", 31, "ESP32-E22", "esptool/targets/esp32e22.py"));
    }

    public static EspFlashLayoutRegistry defaults() {
        return DEFAULT_INSTANCE;
    }

    public synchronized void register(EspFlashLayoutProvider provider) {
        Objects.requireNonNull(provider, "provider");
        byChipId.put(provider.chipId(), provider);
        bySeries.put(provider.profile().series().toLowerCase(), provider);
        bySeries.put(provider.providerId().toLowerCase(), provider);
    }

    public synchronized Optional<EspFlashLayoutProvider> findByChipId(int chipId) {
        return Optional.ofNullable(byChipId.get(chipId));
    }

    public synchronized Optional<EspFlashLayoutProvider> findBySeries(String series) {
        if (series == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(bySeries.get(series.trim().toLowerCase()));
    }

    public synchronized EspFlashLayoutProvider requireByChipId(int chipId) {
        return findByChipId(chipId).orElseThrow(() ->
                new IllegalArgumentException("No layout provider registered for ESP chip ID " + chipId));
    }

    public synchronized List<EspFlashLayoutProvider> allProviders() {
        return List.copyOf(byChipId.values());
    }
}
