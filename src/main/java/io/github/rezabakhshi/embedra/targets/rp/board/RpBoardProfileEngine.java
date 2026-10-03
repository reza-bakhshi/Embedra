package io.github.rezabakhshi.embedra.targets.rp.board;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpSiliconRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure engine that plans and validates official and third-party board profile configurations
 * layered over exact Raspberry Pi silicon parts without mutating underlying silicon models.
 */
public final class RpBoardProfileEngine {

    public static final long FLASH_BASE = 0x10000000L;

    public static final long MAX_EXTERNAL_FLASH_BYTES = 16 * 1024 * 1024L;

    private RpBoardProfileEngine() {
    }

    /**
     * Plans a board layout pairing an exact silicon record with a board profile.
     * Fails closed if the board profile does not target the given silicon part.
     */
    public static RpBoardPlan plan(RpBoardProfile profile, RpSiliconRecord silicon) throws DiagnosticException {
        Objects.requireNonNull(profile, "profile must not be null");
        Objects.requireNonNull(silicon, "silicon must not be null");

        if (!profile.siliconPart().equalsIgnoreCase(silicon.exactPart())) {
            throw new DiagnosticException(
                    Diagnostic.error(DiagnosticCode.RP_BOARD_MISMATCH,
                            "Board profile " + profile.profileId() + " specifies silicon "
                                    + profile.siliconPart() + " but attempted to pair with " + silicon.exactPart()));
        }

        if (profile.externalFlashBytes() <= 0 || profile.externalFlashBytes() > MAX_EXTERNAL_FLASH_BYTES) {
            throw new DiagnosticException(
                    Diagnostic.error(DiagnosticCode.RP_CATALOG_INVALID,
                            "Board profile " + profile.profileId() + " has invalid external flash bounds: "
                                    + profile.externalFlashBytes()));
        }

        List<RpPinAllocation> pins = resolvePinAllocations(profile);
        return new RpBoardPlan(
                profile,
                silicon,
                FLASH_BASE,
                profile.externalFlashBytes(),
                profile.externalFlashInterface(),
                profile.externalFlashChip(),
                pins,
                Optional.ofNullable(profile.wirelessChip()));
    }

    /**
     * Resolves and plans a board profile from a device catalog.
     */
    public static Optional<RpBoardPlan> plan(String profileId, RpDeviceCatalog catalog)
            throws DiagnosticException {
        Objects.requireNonNull(catalog, "catalog must not be null");
        if (profileId == null || profileId.isBlank()) {
            return Optional.empty();
        }
        Optional<RpBoardProfile> profileOpt = catalog.findBoardProfile(profileId.trim());
        if (profileOpt.isEmpty()) {
            return Optional.empty();
        }
        RpBoardProfile profile = profileOpt.get();
        RpSiliconRecord silicon = catalog.requireExactPart(profile.siliconPart());
        return Optional.of(plan(profile, silicon));
    }

    /**
     * Resolves and plans a board profile with explicit silicon validation from a device catalog.
     */
    public static Optional<RpBoardPlan> plan(String profileId, String siliconPart, RpDeviceCatalog catalog)
            throws DiagnosticException {
        Objects.requireNonNull(catalog, "catalog must not be null");
        if (profileId == null || profileId.isBlank()) {
            return Optional.empty();
        }
        Optional<RpBoardProfile> profileOpt = catalog.findBoardProfile(profileId.trim());
        if (profileOpt.isEmpty()) {
            return Optional.empty();
        }
        RpBoardProfile profile = profileOpt.get();
        RpSiliconRecord silicon;
        if (siliconPart != null && !siliconPart.isBlank()) {
            Optional<RpSiliconRecord> siliconOpt = catalog.findExactPart(siliconPart.trim());
            if (siliconOpt.isEmpty()) {
                throw new DiagnosticException(
                        Diagnostic.error(DiagnosticCode.RP_TARGET_UNSUPPORTED,
                                "Unknown Raspberry Pi silicon part: " + siliconPart));
            }
            silicon = siliconOpt.get();
        } else {
            silicon = catalog.requireExactPart(profile.siliconPart());
        }
        return Optional.of(plan(profile, silicon));
    }

    /**
     * Checks if a board profile is compatible with an exact silicon record.
     */
    public static boolean isCompatible(RpBoardProfile profile, RpSiliconRecord silicon) {
        if (profile == null || silicon == null) {
            return false;
        }
        return profile.siliconPart().equalsIgnoreCase(silicon.exactPart());
    }

    /**
     * Resolves documented pin allocations for a board profile (LED, wireless bus, power management).
     */
    public static List<RpPinAllocation> resolvePinAllocations(RpBoardProfile profile) {
        Objects.requireNonNull(profile, "profile must not be null");
        List<RpPinAllocation> pins = new ArrayList<>();

        if (profile.ledGpio() != null) {
            pins.add(new RpPinAllocation(
                    profile.ledGpio(),
                    "GPIO" + profile.ledGpio(),
                    "USER_LED",
                    "On-board User LED (Active High)"));
        }

        if (profile.hasWireless()) {
            // Documented Raspberry Pi Pico W / Pico 2 W wireless subsystem pinout
            pins.add(new RpPinAllocation(
                    23,
                    "WL_ON",
                    "WIRELESS_POWER",
                    "Infineon CYW43439 Power Enable / Regulator Mode"));
            pins.add(new RpPinAllocation(
                    24,
                    "WL_DATA",
                    "WIRELESS_DATA",
                    "Infineon CYW43439 SPI Data / IRQ Line"));
            pins.add(new RpPinAllocation(
                    25,
                    "WL_CS",
                    "WIRELESS_CS",
                    "Infineon CYW43439 SPI Chip Select"));
            pins.add(new RpPinAllocation(
                    29,
                    "WL_CLK",
                    "WIRELESS_CLOCK",
                    "Infineon CYW43439 SPI Clock / ADC Shared Line"));
        }

        return List.copyOf(pins);
    }
}
