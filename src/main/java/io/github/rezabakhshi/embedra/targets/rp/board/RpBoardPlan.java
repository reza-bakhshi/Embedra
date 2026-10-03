package io.github.rezabakhshi.embedra.targets.rp.board;

import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpSiliconRecord;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpWirelessInfo;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A reviewed, immutable board plan pairing exact silicon with board-level external flash,
 * interface routing, pin allocations, and companion wireless hardware.
 */
public record RpBoardPlan(
        RpBoardProfile profile,
        RpSiliconRecord silicon,
        long flashBase,
        long flashBytes,
        String flashInterface,
        String flashChip,
        List<RpPinAllocation> pinAllocations,
        Optional<RpWirelessInfo> wirelessChip) {

    public RpBoardPlan {
        Objects.requireNonNull(profile, "profile must not be null");
        Objects.requireNonNull(silicon, "silicon must not be null");
        Objects.requireNonNull(flashInterface, "flashInterface must not be null");
        Objects.requireNonNull(flashChip, "flashChip must not be null");
        Objects.requireNonNull(pinAllocations, "pinAllocations must not be null");
        Objects.requireNonNull(wirelessChip, "wirelessChip must not be null");
        pinAllocations = List.copyOf(pinAllocations);
        if (flashBytes <= 0) {
            throw new IllegalArgumentException("flashBytes must be positive: " + flashBytes);
        }
    }

    public boolean hasWireless() {
        return wirelessChip.isPresent();
    }
}
