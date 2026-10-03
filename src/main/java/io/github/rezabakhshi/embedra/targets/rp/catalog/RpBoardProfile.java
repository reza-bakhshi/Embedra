package io.github.rezabakhshi.embedra.targets.rp.catalog;

import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import java.util.Objects;

/**
 * An official or third-party board profile layering external flash and peripherals
 * over an exact Raspberry Pi silicon part.
 */
public record RpBoardProfile(
        String profileId,
        String boardName,
        String vendor,
        String siliconPart,
        long externalFlashBytes,
        String externalFlashChip,
        String externalFlashInterface,
        RpWirelessInfo wirelessChip,
        Integer ledGpio,
        SupportState supportState,
        String documentationUrl) {

    public RpBoardProfile {
        Objects.requireNonNull(profileId, "profileId must not be null");
        Objects.requireNonNull(boardName, "boardName must not be null");
        Objects.requireNonNull(vendor, "vendor must not be null");
        Objects.requireNonNull(siliconPart, "siliconPart must not be null");
        Objects.requireNonNull(externalFlashChip, "externalFlashChip must not be null");
        Objects.requireNonNull(externalFlashInterface, "externalFlashInterface must not be null");
        Objects.requireNonNull(supportState, "supportState must not be null");

        if (externalFlashBytes <= 0) {
            throw new IllegalArgumentException("externalFlashBytes must be positive: " + externalFlashBytes);
        }
    }

    /**
     * Checks if this board includes a wireless companion chip.
     */
    public boolean hasWireless() {
        return wirelessChip != null;
    }
}
