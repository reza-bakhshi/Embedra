package io.github.rezabakhshi.embedra.targets.nordic.dualcore;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import java.util.Objects;

/**
 * Immutable layout representing dual-core partitions (Application and Network cores) for nRF5340.
 */
public record NordicDualCoreLayout(
        NordicPartRecord part,
        AddressRange appCoreFlash,
        AddressRange appCoreRam,
        AddressRange netCoreFlashGlobal,
        AddressRange netCoreFlashLocal,
        AddressRange netCoreRamGlobal,
        AddressRange netCoreRamLocal,
        int ipcChannels) {

    public NordicDualCoreLayout {
        Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(appCoreFlash, "appCoreFlash must not be null");
        Objects.requireNonNull(appCoreRam, "appCoreRam must not be null");
        Objects.requireNonNull(netCoreFlashGlobal, "netCoreFlashGlobal must not be null");
        Objects.requireNonNull(netCoreFlashLocal, "netCoreFlashLocal must not be null");
        Objects.requireNonNull(netCoreRamGlobal, "netCoreRamGlobal must not be null");
        Objects.requireNonNull(netCoreRamLocal, "netCoreRamLocal must not be null");
    }
}
