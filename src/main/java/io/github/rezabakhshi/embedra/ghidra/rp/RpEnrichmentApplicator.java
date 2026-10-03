package io.github.rezabakhshi.embedra.ghidra.rp;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.rp.RpComponentEnrichmentReport;
import io.github.rezabakhshi.embedra.analyzers.rp.RpCyw43Match;
import io.github.rezabakhshi.embedra.analyzers.rp.RpLwIpMatch;
import io.github.rezabakhshi.embedra.analyzers.rp.RpTinyUsbMatch;
import io.github.rezabakhshi.embedra.analyzers.rp.UsbDescriptorInfo;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.rp.binaryinfo.RpBinaryInfoBlockDevice;
import io.github.rezabakhshi.embedra.targets.rp.binaryinfo.RpBinaryInfoPin;
import io.github.rezabakhshi.embedra.targets.rp.binaryinfo.RpBinaryInfoResult;
import io.github.rezabakhshi.embedra.targets.rp.board.RpBoardPlan;
import io.github.rezabakhshi.embedra.targets.rp.board.RpPinAllocation;
import java.util.Objects;
import java.util.Optional;

/**
 * Applies board profile metadata, Pico SDK binary info properties, and component bookmarks to a Ghidra program.
 */
public final class RpEnrichmentApplicator {

    public static final String BOARD_OPTIONS_CATEGORY = "Embedra RP Board";

    public static final String PICO_SDK_OPTIONS_CATEGORY = "Embedra Pico SDK";

    public static final String COMPONENTS_OPTIONS_CATEGORY = "Embedra RP Components";

    public static final String BOOKMARK_CAT_BOARD_PINOUT = "Embedra Board Pinout";

    public static final String BOOKMARK_CAT_PICO_SDK = "Embedra Pico SDK";

    public static final String BOOKMARK_CAT_PICO_PINOUT = "Embedra Pico Pinout";

    public static final String BOOKMARK_CAT_TINYUSB = "Embedra TinyUSB";

    public static final String BOOKMARK_CAT_LWIP = "Embedra lwIP";

    public static final String BOOKMARK_CAT_CYW43 = "Embedra CYW43";

    private RpEnrichmentApplicator() {
    }

    public static void apply(
            Program program,
            Optional<RpBoardPlan> boardPlan,
            RpBinaryInfoResult binaryInfo,
            RpComponentEnrichmentReport components,
            TaskMonitor monitor) throws RpMappingException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(boardPlan, "boardPlan must not be null");
        Objects.requireNonNull(binaryInfo, "binaryInfo must not be null");
        Objects.requireNonNull(components, "components must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        monitor.checkCancelled();

        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Apply Raspberry Pi Board and SDK enrichments")) {

            boardPlan.ifPresent(plan -> applyBoardPlan(program, plan));
            monitor.checkCancelled();

            if (binaryInfo.present()) {
                applyBinaryInfo(program, binaryInfo);
            }
            monitor.checkCancelled();

            if (components.hasAnyComponentDetected()) {
                applyComponents(program, components);
            }
            monitor.checkCancelled();

            transaction.commit();
        }
    }

    private static void applyBoardPlan(Program program, RpBoardPlan plan) {
        var options = program.getOptions(BOARD_OPTIONS_CATEGORY);
        options.setString("Board Profile ID", plan.profile().profileId());
        options.setString("Board Name", plan.profile().boardName());
        options.setString("Board Vendor", plan.profile().vendor());
        options.setLong("External Flash Bytes", plan.flashBytes());
        options.setString("External Flash Chip", plan.flashChip());
        options.setString("External Flash Interface", plan.flashInterface());
        options.setString("Underlying Silicon Part", plan.silicon().exactPart());

        if (plan.profile().ledGpio() != null) {
            options.setInt("LED GPIO", plan.profile().ledGpio());
        }

        plan.wirelessChip().ifPresent(wireless -> {
            options.setString("Wireless Model", wireless.model());
            options.setString("Wireless Wi-Fi", wireless.wifi());
            options.setString("Wireless Bluetooth", wireless.bluetooth());
            options.setString("Wireless Interfaces", String.join(", ", wireless.interfaces()));
        });

        // Also record board info in common RP firmware options
        var fwOptions = program.getOptions(RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY);
        fwOptions.setString("Board Profile", plan.profile().profileId());
        fwOptions.setString("Board Name", plan.profile().boardName());

        // Bookmarks for board pin allocations
        Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(plan.flashBase());
        if (program.getMemory().contains(baseAddr)) {
            for (RpPinAllocation pin : plan.pinAllocations()) {
                String comment = String.format("Board Pin: %s (GPIO %d) - %s [%s]",
                        pin.name(), pin.pin(), pin.description(), pin.role());
                String category = BOOKMARK_CAT_BOARD_PINOUT + ": " + pin.name();
                setBookmarkIfAbsent(program, baseAddr, category, comment);
            }
        }
    }

    private static void applyBinaryInfo(Program program, RpBinaryInfoResult binaryInfo) {
        var options = program.getOptions(PICO_SDK_OPTIONS_CATEGORY);
        binaryInfo.programName().ifPresent(v -> options.setString("Program Name", v));
        binaryInfo.programVersion().ifPresent(v -> options.setString("Program Version", v));
        binaryInfo.programBuildDate().ifPresent(v -> options.setString("Build Date", v));
        binaryInfo.programUrl().ifPresent(v -> options.setString("Program URL", v));
        binaryInfo.programDescription().ifPresent(v -> options.setString("Program Description", v));
        binaryInfo.sdkVersion().ifPresent(v -> options.setString("SDK Version", v));
        binaryInfo.picoBoard().ifPresent(v -> options.setString("Pico Board", v));
        binaryInfo.boot2Name().ifPresent(v -> options.setString("Boot2 Name", v));
        binaryInfo.binaryEnd().ifPresent(v -> options.setLong("Binary End Address", v));

        if (!binaryInfo.programFeatures().isEmpty()) {
            options.setString("Features", String.join(", ", binaryInfo.programFeatures()));
        }
        if (!binaryInfo.buildAttributes().isEmpty()) {
            options.setString("Build Attributes", String.join(", ", binaryInfo.buildAttributes()));
        }

        // Bookmark at binary info header
        Address headerAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
                binaryInfo.headerAddress());
        if (program.getMemory().contains(headerAddr)) {
            String comment = String.format("Pico SDK Binary Info Header (Program: %s, Version: %s, SDK: %s)",
                    binaryInfo.programName().orElse("unknown"),
                    binaryInfo.programVersion().orElse("unknown"),
                    binaryInfo.sdkVersion().orElse("unknown"));
            setBookmarkIfAbsent(program, headerAddr, BOOKMARK_CAT_PICO_SDK, comment);
        }

        // Bookmarks for pin definitions
        for (RpBinaryInfoPin pin : binaryInfo.pins()) {
            String comment = String.format("Pico SDK Pin Mask: 0x%X -> %s", pin.pinMask(), pin.label());
            String category = BOOKMARK_CAT_PICO_PINOUT + ": " + pin.label();
            setBookmarkIfAbsent(program, headerAddr, category, comment);
        }

        // Block devices
        for (RpBinaryInfoBlockDevice dev : binaryInfo.blockDevices()) {
            Address devAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(dev.address());
            if (program.getMemory().contains(devAddr)) {
                String comment = String.format("Pico SDK Block Device: %s (Size: %d bytes, Flags: 0x%X)",
                        dev.name(), dev.size(), dev.flags());
                setBookmarkIfAbsent(program, devAddr, BOOKMARK_CAT_PICO_SDK, comment);
            }
        }
    }

    private static void applyComponents(Program program, RpComponentEnrichmentReport report) {
        var options = program.getOptions(COMPONENTS_OPTIONS_CATEGORY);
        Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);

        // 1. TinyUSB
        RpTinyUsbMatch tinyUsb = report.tinyUsb();
        if (tinyUsb.detected()) {
            options.setBoolean("TinyUSB Detected", true);
            options.setString("TinyUSB Confidence", tinyUsb.confidence().name());
            options.setInt("TinyUSB Descriptors Found", tinyUsb.descriptors().size());
            if (!tinyUsb.apis().isEmpty()) {
                options.setString("TinyUSB APIs", String.join(", ", tinyUsb.apis()));
            }

            for (UsbDescriptorInfo desc : tinyUsb.descriptors()) {
                Address descAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(desc.address());
                if (program.getMemory().contains(descAddr)) {
                    setBookmarkIfAbsent(program, descAddr, BOOKMARK_CAT_TINYUSB, desc.description());
                }
            }
            if (tinyUsb.descriptors().isEmpty() && program.getMemory().contains(baseAddr)) {
                setBookmarkIfAbsent(program, baseAddr, BOOKMARK_CAT_TINYUSB,
                        "TinyUSB stack detected (" + tinyUsb.confidence() + ")");
            }
        }

        // 2. lwIP
        RpLwIpMatch lwIp = report.lwIp();
        if (lwIp.detected()) {
            options.setBoolean("lwIP Detected", true);
            options.setString("lwIP Confidence", lwIp.confidence().name());
            lwIp.version().ifPresent(v -> options.setString("lwIP Version", v));
            if (!lwIp.protocols().isEmpty()) {
                options.setString("lwIP Protocols", String.join(", ", lwIp.protocols()));
            }
            if (!lwIp.apis().isEmpty()) {
                options.setString("lwIP APIs", String.join(", ", lwIp.apis()));
            }

            if (program.getMemory().contains(baseAddr)) {
                String comment = String.format("lwIP Network Stack (Version: %s, Protocols: %s)",
                        lwIp.version().orElse("unknown"),
                        String.join(", ", lwIp.protocols()));
                setBookmarkIfAbsent(program, baseAddr, BOOKMARK_CAT_LWIP, comment);
            }
        }

        // 3. CYW43
        RpCyw43Match cyw43 = report.cyw43();
        if (cyw43.detected()) {
            options.setBoolean("CYW43 Detected", true);
            options.setString("CYW43 Model", cyw43.chipModel());
            options.setString("CYW43 Confidence", cyw43.confidence().name());
            cyw43.busInterface().ifPresent(bus -> options.setString("CYW43 Bus Interface", bus));
            options.setBoolean("CYW43 Firmware Blob Present", cyw43.firmwareBlobPresent());
            if (!cyw43.countryCodes().isEmpty()) {
                options.setString("CYW43 Country Codes", String.join(", ", cyw43.countryCodes()));
            }
            if (!cyw43.apis().isEmpty()) {
                options.setString("CYW43 APIs", String.join(", ", cyw43.apis()));
            }

            if (program.getMemory().contains(baseAddr)) {
                String comment = String.format("%s Wireless Driver (Bus: %s, Firmware: %s)",
                        cyw43.chipModel(),
                        cyw43.busInterface().orElse("SPI/PIO"),
                        cyw43.firmwareBlobPresent() ? "embedded" : "standard");
                setBookmarkIfAbsent(program, baseAddr, BOOKMARK_CAT_CYW43, comment);
            }
        }
    }

    private static void setBookmarkIfAbsent(Program program, Address address, String category, String comment) {
        Bookmark[] existing = program.getBookmarkManager().getBookmarks(address, BookmarkType.INFO);
        for (Bookmark bm : existing) {
            if (category.equals(bm.getCategory()) && comment.equals(bm.getComment())) {
                return; // Already present, idempotent
            }
        }
        program.getBookmarkManager().setBookmark(address, BookmarkType.INFO, category, comment);
    }
}
