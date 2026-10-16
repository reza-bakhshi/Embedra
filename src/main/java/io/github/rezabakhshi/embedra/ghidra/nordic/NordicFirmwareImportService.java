package io.github.rezabakhshi.embedra.ghidra.nordic;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.ghidra.nordic.NordicInputDecoder.DecodedNordicFirmware;
import io.github.rezabakhshi.embedra.ghidra.nordic.NordicInputDecoder.DecodedSegment;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicCatalogRegistry;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import io.github.rezabakhshi.embedra.targets.nordic.dualcore.NordicDualCoreAnalyzer;
import io.github.rezabakhshi.embedra.targets.nordic.memory.NordicMemoryPlan;
import io.github.rezabakhshi.embedra.targets.nordic.memory.NordicMemoryPlanner;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicDefaultPacks;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicDevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.nordic.peripheral.NordicPeripheralPack;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;
import java.util.Optional;

/**
 * High-level orchestration service for importing Nordic Semiconductor firmware into Ghidra.
 */
public final class NordicFirmwareImportService {

    private final NordicCatalogRegistry catalogRegistry;

    private final NordicDevicePackRegistry packRegistry;

    private final NordicFirmwareMapper mapper;

    public NordicFirmwareImportService() {
        this(loadDefaultCatalogSafe(), loadDefaultPacksSafe(), new NordicFirmwareMapper());
    }

    public NordicFirmwareImportService(
            NordicCatalogRegistry catalogRegistry,
            NordicDevicePackRegistry packRegistry,
            NordicFirmwareMapper mapper) {
        this.catalogRegistry = Objects.requireNonNull(catalogRegistry, "catalogRegistry must not be null");
        this.packRegistry = Objects.requireNonNull(packRegistry, "packRegistry must not be null");
        this.mapper = Objects.requireNonNull(mapper, "mapper must not be null");
    }

    public static NordicCatalogRegistry loadDefaultCatalogSafe() {
        try {
            return NordicCatalogRegistry.loadDefault();
        } catch (DiagnosticException e) {
            return new NordicCatalogRegistry(java.util.List.of());
        }
    }

    public static NordicDevicePackRegistry loadDefaultPacksSafe() {
        try {
            return NordicDevicePackRegistry.loadDefault();
        } catch (DiagnosticException e) {
            return new NordicDevicePackRegistry(java.util.List.of());
        }
    }

    public NordicCatalogRegistry catalogRegistry() {
        return catalogRegistry;
    }

    public NordicDevicePackRegistry packRegistry() {
        return packRegistry;
    }

    public NordicFirmwareMapper mapper() {
        return mapper;
    }

    /**
     * Imports a single firmware image into the target program.
     */
    public NordicImportReport importFirmware(
            Program program,
            byte[] input,
            String targetPartOverride,
            ParserLimits limits,
            TaskMonitor monitor) throws NordicMappingException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(input, "input must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        monitor.checkCancelled();

        DecodedNordicFirmware decoded = NordicInputDecoder.decode(input, limits);

        NordicPartRecord part = resolvePart(decoded, targetPartOverride);
        NordicMemoryPlan memoryPlan;
        try {
            memoryPlan = NordicMemoryPlanner.plan(part, limits, CancellationToken.none());
        } catch (DiagnosticException e) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_MAPPING_FAILED,
                "Failed to plan memory layout for " + part.exactPart() + ": " + e.getMessage(), e
            );
        }

        NordicPeripheralPack pack = packRegistry.packForSeries(part.series())
            .orElseGet(() -> NordicDefaultPacks.forSeries(part.series()));

        return mapper.map(program, part, memoryPlan, pack, decoded, monitor);
    }

    /**
     * Imports a dual-core nRF5340 firmware pair (Application core and Network core) into separate programs,
     * cross-linking them via shared IPC channels.
     */
    public void importDualCorePair(
            Program appProgram,
            byte[] appInput,
            Program netProgram,
            byte[] netInput,
            String targetPartOverride,
            ParserLimits limits,
            TaskMonitor monitor) throws NordicMappingException, CancelledException {
        Objects.requireNonNull(appProgram, "appProgram must not be null");
        Objects.requireNonNull(appInput, "appInput must not be null");
        Objects.requireNonNull(netProgram, "netProgram must not be null");
        Objects.requireNonNull(netInput, "netInput must not be null");

        String partId = (targetPartOverride != null && !targetPartOverride.isBlank())
            ? targetPartOverride.trim() : "nRF5340-QKAA";

        // Import both cores
        importFirmware(appProgram, appInput, partId, limits, monitor);
        importFirmware(netProgram, netInput, partId, limits, monitor);

        // Cross-link via IPC channels
        bindDualCorePrograms(appProgram, netProgram);
    }

    /**
     * Imports an ARM TrustZone firmware pair (Secure and Non-Secure) for nRF9160 or nRF5340.
     */
    public void importTrustZonePair(
            Program secureProgram,
            byte[] secureInput,
            Program nonSecureProgram,
            byte[] nonSecureInput,
            String targetPartOverride,
            ParserLimits limits,
            TaskMonitor monitor) throws NordicMappingException, CancelledException {
        Objects.requireNonNull(secureProgram, "secureProgram must not be null");
        Objects.requireNonNull(secureInput, "secureInput must not be null");
        Objects.requireNonNull(nonSecureProgram, "nonSecureProgram must not be null");
        Objects.requireNonNull(nonSecureInput, "nonSecureInput must not be null");

        String partId = (targetPartOverride != null && !targetPartOverride.isBlank())
            ? targetPartOverride.trim() : "nRF9160-SICA";

        importFirmware(secureProgram, secureInput, partId, limits, monitor);
        importFirmware(nonSecureProgram, nonSecureInput, partId, limits, monitor);

        bindTrustZonePrograms(secureProgram, nonSecureProgram);
    }

    private NordicPartRecord resolvePart(DecodedNordicFirmware decoded, String override) {
        if (override != null && !override.isBlank()) {
            Optional<NordicPartRecord> found = catalogRegistry.findExactPart(override.trim());
            if (found.isPresent()) {
                return found.get();
            }
        }

        // Auto-detection heuristics based on decoded segments and entry vectors
        for (DecodedSegment seg : decoded.segments()) {
            if (seg.address() == NordicDualCoreAnalyzer.NET_FLASH_GLOBAL_BASE) {
                return catalogRegistry.findExactPart("nRF5340-QKAA")
                    .orElseGet(NordicPartRecord::defaultNrf5340);
            }
            if (seg.address() == 0x00040000L) { // nRF9160 Non-Secure flash partition
                return catalogRegistry.findExactPart("nRF9160-SICA")
                    .orElseGet(NordicPartRecord::defaultNrf9160);
            }
        }

        if (decoded.relocatedAppOffset().isPresent()) {
            long appOffset = decoded.relocatedAppOffset().get();
            if (appOffset == 0x00027000L) { // S140
                return catalogRegistry.findExactPart("nRF52840-QIAA")
                    .orElseGet(NordicPartRecord::defaultNrf52840);
            }
            if (appOffset == 0x00026000L) { // S132
                return catalogRegistry.findExactPart("nRF52832-QFAA")
                    .orElseGet(NordicPartRecord::defaultNrf52832);
            }
            if (appOffset == 0x00019000L) { // S112
                return catalogRegistry.findExactPart("nRF52810-QFAA")
                    .orElseGet(NordicPartRecord::defaultNrf52832);
            }
        }

        // Check initial SP in base segment
        for (DecodedSegment seg : decoded.segments()) {
            if (seg.address() == 0x00000000L && seg.data().length >= 4) {
                ByteBuffer bb = ByteBuffer.wrap(seg.data()).order(ByteOrder.LITTLE_ENDIAN);
                long sp = bb.getInt(0) & 0xFFFFFFFFL;
                if (sp == 0x20080000L) {
                    return catalogRegistry.findExactPart("nRF5340-QKAA")
                        .orElseGet(NordicPartRecord::defaultNrf5340);
                }
                if (sp == 0x20040000L) {
                    return catalogRegistry.findExactPart("nRF52840-QIAA")
                        .orElseGet(NordicPartRecord::defaultNrf52840);
                }
                if (sp == 0x20010000L) {
                    return catalogRegistry.findExactPart("nRF52832-QFAA")
                        .orElseGet(NordicPartRecord::defaultNrf52832);
                }
                if (sp == 0x20004000L) {
                    return catalogRegistry.findExactPart("nRF51822-QFAA")
                        .orElseGet(NordicPartRecord::defaultNrf51822);
                }
            }
        }

        if (decoded.maxAddress() > 524288L) {
            return catalogRegistry.findExactPart("nRF52840-QIAA")
                .orElseGet(NordicPartRecord::defaultNrf52840);
        }

        return catalogRegistry.findExactPart("nRF52832-QFAA")
            .orElseGet(NordicPartRecord::defaultNrf52832);
    }

    private void bindDualCorePrograms(Program appProgram, Program netProgram) {
        try (GhidraProgramTransaction txApp = GhidraProgramTransaction.start(
                appProgram, "Annotate Dual-Core cross links");
             GhidraProgramTransaction txNet = GhidraProgramTransaction.start(
                netProgram, "Annotate Dual-Core cross links")) {

            var appOpts = appProgram.getOptions(NordicFirmwareMapper.OPTIONS_CATEGORY);
            appOpts.setString("Dual-Core Peer Role", "Network Core");
            appOpts.setString("Dual-Core Peer Program", netProgram.getName());

            var netOpts = netProgram.getOptions(NordicFirmwareMapper.OPTIONS_CATEGORY);
            netOpts.setString("Dual-Core Peer Role", "Application Core");
            netOpts.setString("Dual-Core Peer Program", appProgram.getName());

            // Annotate IPC peripheral channels (0x4002A000 in App, 0x41012000 in Net)
            Address appIpc = appProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x4002A000L);
            appProgram.getListing().setComment(
                appIpc, CommentType.PLATE,
                "IPC (Inter-Processor Communication) linked to Network Core program " + netProgram.getName()
            );

            Address netIpc = netProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x41012000L);
            netProgram.getListing().setComment(
                netIpc, CommentType.PLATE,
                "IPC (Inter-Processor Communication) linked to Application Core program " + appProgram.getName()
            );

            txApp.commit();
            txNet.commit();
        }
    }

    private void bindTrustZonePrograms(Program secProgram, Program nsProgram) {
        try (GhidraProgramTransaction txSec = GhidraProgramTransaction.start(
                secProgram, "Annotate TrustZone cross links");
             GhidraProgramTransaction txNs = GhidraProgramTransaction.start(
                nsProgram, "Annotate TrustZone cross links")) {

            var secOpts = secProgram.getOptions(NordicFirmwareMapper.OPTIONS_CATEGORY);
            secOpts.setString("TrustZone Peer Domain", "Non-Secure");
            secOpts.setString("TrustZone Peer Program", nsProgram.getName());

            var nsOpts = nsProgram.getOptions(NordicFirmwareMapper.OPTIONS_CATEGORY);
            nsOpts.setString("TrustZone Peer Domain", "Secure");
            nsOpts.setString("TrustZone Peer Program", secProgram.getName());

            txSec.commit();
            txNs.commit();
        }
    }
}
