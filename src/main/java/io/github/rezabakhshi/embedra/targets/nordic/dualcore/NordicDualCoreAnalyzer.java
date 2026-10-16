package io.github.rezabakhshi.embedra.targets.nordic.dualcore;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import java.util.Objects;

/**
 * Pure analyzer for dual-core firmware layout partitioning and IPC validation.
 */
public final class NordicDualCoreAnalyzer {

    public static final long APP_FLASH_BASE = 0x00000000L;

    public static final long APP_FLASH_SIZE = 1048576L; // 1 MiB

    public static final long APP_RAM_BASE = 0x20000000L;

    public static final long APP_RAM_SIZE = 524288L;   // 512 KiB

    public static final long NET_FLASH_GLOBAL_BASE = 0x01000000L;

    public static final long NET_FLASH_LOCAL_BASE = 0x00000000L;

    public static final long NET_FLASH_SIZE = 262144L; // 256 KiB

    public static final long NET_RAM_GLOBAL_BASE = 0x21000000L;

    public static final long NET_RAM_LOCAL_BASE = 0x20000000L;

    public static final long NET_RAM_SIZE = 65536L;    // 64 KiB

    public static final int DEFAULT_IPC_CHANNELS = 16;

    private NordicDualCoreAnalyzer() {
    }

    public static NordicDualCoreLayout buildLayout(NordicPartRecord part) throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        if (!part.dualCore()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_TOPOLOGY_INVALID,
                "Part " + part.exactPart() + " is not a dual-core SoC",
                null));
        }

        return new NordicDualCoreLayout(
            part,
            new AddressRange("default", APP_FLASH_BASE, APP_FLASH_SIZE),
            new AddressRange("default", APP_RAM_BASE, APP_RAM_SIZE),
            new AddressRange("default", NET_FLASH_GLOBAL_BASE, NET_FLASH_SIZE),
            new AddressRange("default", NET_FLASH_LOCAL_BASE, NET_FLASH_SIZE),
            new AddressRange("default", NET_RAM_GLOBAL_BASE, NET_RAM_SIZE),
            new AddressRange("default", NET_RAM_LOCAL_BASE, NET_RAM_SIZE),
            DEFAULT_IPC_CHANNELS
        );
    }

    public static boolean isNetworkCoreAddress(long address) {
        // Global network Flash aperture 0x01000000 - 0x0103FFFF or RAM 0x21000000 - 0x2100FFFF
        boolean inNetFlash = address >= NET_FLASH_GLOBAL_BASE && address < (NET_FLASH_GLOBAL_BASE + NET_FLASH_SIZE);
        boolean inNetRam = address >= NET_RAM_GLOBAL_BASE && address < (NET_RAM_GLOBAL_BASE + NET_RAM_SIZE);
        return inNetFlash || inNetRam;
    }

    public static boolean isApplicationCoreAddress(long address) {
        boolean inAppFlash = address >= APP_FLASH_BASE && address < (APP_FLASH_BASE + APP_FLASH_SIZE);
        boolean inAppRam = address >= APP_RAM_BASE && address < (APP_RAM_BASE + APP_RAM_SIZE);
        return inAppFlash || inAppRam;
    }
}
