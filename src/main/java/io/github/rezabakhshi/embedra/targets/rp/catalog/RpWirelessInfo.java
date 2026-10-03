package io.github.rezabakhshi.embedra.targets.rp.catalog;

import java.util.List;
import java.util.Objects;

/**
 * Wireless companion chip details attached to a Raspberry Pi board profile.
 */
public record RpWirelessInfo(
        String model,
        List<String> interfaces,
        String wifi,
        String bluetooth) {

    public RpWirelessInfo {
        Objects.requireNonNull(model, "model must not be null");
        interfaces = List.copyOf(interfaces != null ? interfaces : List.of());
    }
}
