package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import java.util.Objects;

/**
 * Known external hardware secure element definition (AN-013).
 *
 * @param elementId unique element identifier (e.g. "ATECC608A", "OPTIGA_TRUST_M")
 * @param manufacturer manufacturer name (e.g. "Microchip", "Infineon", "NXP")
 * @param model exact model string
 * @param i2cDefaultAddress 7-bit default I2C slave address
 * @param algorithm supported asymmetric or key ladder primitive
 * @param description functional description
 */
public record SecureElementDefinition(
        String elementId,
        String manufacturer,
        String model,
        int i2cDefaultAddress,
        CryptoAlgorithm algorithm,
        String description) {

    public SecureElementDefinition {
        Objects.requireNonNull(elementId, "elementId must not be null");
        Objects.requireNonNull(manufacturer, "manufacturer must not be null");
        Objects.requireNonNull(model, "model must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(description, "description must not be null");
        if (i2cDefaultAddress < 0 || i2cDefaultAddress > 0x7F) {
            throw new IllegalArgumentException("Invalid 7-bit I2C address: " + i2cDefaultAddress);
        }
    }
}
