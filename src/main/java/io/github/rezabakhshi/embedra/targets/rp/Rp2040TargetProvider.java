package io.github.rezabakhshi.embedra.targets.rp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.BootRelationship;
import io.github.rezabakhshi.embedra.core.model.BootRelationshipType;
import io.github.rezabakhshi.embedra.core.model.CommunicationKind;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.InterProcessorLink;
import io.github.rezabakhshi.embedra.core.model.ProcessorGroup;
import io.github.rezabakhshi.embedra.core.model.ProcessorGroupKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.core.model.SecurityDomainKind;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpSiliconRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Pure target provider for the dual Cortex-M0+ Raspberry Pi RP2040 microcontroller.
 */
public final class Rp2040TargetProvider implements RpTargetProvider {

    public static final String PROVIDER_ID = "raspberrypi.rp2040";

    public static final String ARCH_ARM = "ARM_CORTEX_M0P";

    public static final String ADDRESS_SPACE = "default";

    private final RpSiliconRecord silicon;

    public Rp2040TargetProvider(RpSiliconRecord silicon) {
        this.silicon = Objects.requireNonNull(silicon, "silicon must not be null");
        if (!"RP2040".equalsIgnoreCase(silicon.exactPart())) {
            throw new IllegalArgumentException(
                    "Rp2040TargetProvider requires RP2040 silicon record: " + silicon.exactPart());
        }
    }

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public String series() {
        return "RP2040";
    }

    @Override
    public RpSiliconRecord siliconRecord() {
        return silicon;
    }

    @Override
    public LanguageSelection selectLanguage(String bootArchitecture) {
        Evidence evidence = new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "rp2040-datasheet",
                "RP2040 Datasheet Section 1.2: Dual ARM Cortex-M0+ processors running ARMv6-M Thumb");
        return new LanguageSelection(
                "ARM:LE:32:v6M",
                "default",
                "ARMv6-M",
                32,
                2,
                "little",
                List.of(evidence));
    }

    @Override
    public List<RpMemoryRegion> memoryRegions(RpBoardProfile boardProfile) {
        long flashBytes = boardProfile != null ? boardProfile.externalFlashBytes() : (2 * 1024 * 1024L);
        List<RpMemoryRegion> regions = new ArrayList<>();

        // Boot ROM (16 KiB)
        regions.add(new RpMemoryRegion(
                "BOOT_ROM", RpMemoryRegionKind.BOOT_ROM,
                new AddressRange(ADDRESS_SPACE, 0x00000000L, 0x4000L),
                true, false, true, "RP2040 Internal Boot ROM (16 KiB)"));

        // External Flash XIP
        regions.add(new RpMemoryRegion(
                "FLASH_XIP", RpMemoryRegionKind.FLASH_XIP,
                new AddressRange(ADDRESS_SPACE, 0x10000000L, flashBytes),
                true, false, true, "QSPI Flash Execute-In-Place Window (" + (flashBytes / (1024 * 1024)) + " MiB)"));

        // XIP Cache Maintenance Registers
        regions.add(new RpMemoryRegion(
                "XIP_MAINTENANCE", RpMemoryRegionKind.XIP_MAINTENANCE,
                new AddressRange(ADDRESS_SPACE, 0x14000000L, 0x1000L),
                true, true, false, "RP2040 Flash XIP Cache Control and Maintenance"));

        // SRAM (264 KiB total: striped 256K banks + 2x 4K non-striped)
        regions.add(new RpMemoryRegion(
                "SRAM", RpMemoryRegionKind.SRAM,
                new AddressRange(ADDRESS_SPACE, 0x20000000L, 264 * 1024L),
                true, true, true, "SRAM Banks 0-5 (264 KiB total: striped 256 KiB + 2x 4 KiB)"));

        // Non-striped SRAM Direct Access Alias (264 KiB)
        regions.add(new RpMemoryRegion(
                "NON_STRIPED_SRAM", RpMemoryRegionKind.SRAM,
                new AddressRange(ADDRESS_SPACE, 0x21000000L, 264 * 1024L),
                true, true, true, "Non-Striped Direct Access SRAM Alias (264 KiB)"));

        // Peripherals (0x40000000 - 0x4005FFFF)
        regions.add(new RpMemoryRegion(
                "PERIPHERALS", RpMemoryRegionKind.PERIPHERALS,
                new AddressRange(ADDRESS_SPACE, 0x40000000L, 0x60000L),
                true, true, false, "RP2040 Hardware Peripherals"));

        // Atomic Aliases (0x50000000 - 0x5005FFFF)
        regions.add(new RpMemoryRegion(
                "ATOMIC_ALIASES", RpMemoryRegionKind.ATOMIC_ALIASES,
                new AddressRange(ADDRESS_SPACE, 0x50000000L, 0x60000L),
                true, true, false, "RP2040 Atomic Register Access Aliases"));

        // SIO (Single-cycle IO)
        regions.add(new RpMemoryRegion(
                "SIO", RpMemoryRegionKind.SIO,
                new AddressRange(ADDRESS_SPACE, 0xD0000000L, 0x180L),
                true, true, false, "RP2040 Single-Cycle IO (FIFOs, Spinlocks, Dividers)"));

        // PPB (Private Peripheral Bus)
        regions.add(new RpMemoryRegion(
                "PPB", RpMemoryRegionKind.PPB,
                new AddressRange(ADDRESS_SPACE, 0xE0000000L, 0x100000L),
                true, true, false, "Cortex-M0+ System Control Space (NVIC, SysTick)"));

        return List.copyOf(regions);
    }

    @Override
    public boolean isAddressMapped(long address, RpBoardProfile boardProfile) {
        return memoryRegions(boardProfile).stream().anyMatch(r -> r.contains(address));
    }

    @Override
    public boolean isValidEntryPoint(long address, String bootArchitecture, RpBoardProfile boardProfile) {
        long alignedAddress = address & ~1L;
        for (RpMemoryRegion region : memoryRegions(boardProfile)) {
            if (region.executable() && region.contains(alignedAddress)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ExecutionTopology buildTopology(String bootArchitecture, RpBoardProfile boardProfile) {
        SecurityDomain domain = new SecurityDomain("rp2040.domain", SecurityDomainKind.NON_SECURE);
        Evidence coreEvidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD, "rp2040-core",
                "RP2040 symmetric dual-core Cortex-M0+");
        Evidence pioEvidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD, "rp2040-pio",
                "RP2040 dual PIO blocks with 4 state machines each");
        Evidence romEvidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD, "rp2040-rom",
                "RP2040 internal 16 KiB boot ROM");

        ProcessorNode core0 = new ProcessorNode(
                "rp2040.core0",
                ProcessorKind.CPU_CORE,
                Optional.of("ARMv6-M"),
                Optional.of("ARM:LE:32:v6M"),
                Optional.of("default"),
                "BOOT_CORE",
                domain,
                "rp2040",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(coreEvidence));

        ProcessorNode core1 = new ProcessorNode(
                "rp2040.core1",
                ProcessorKind.CPU_CORE,
                Optional.of("ARMv6-M"),
                Optional.of("ARM:LE:32:v6M"),
                Optional.of("default"),
                "SECONDARY_CORE",
                domain,
                "rp2040",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(coreEvidence));

        ProcessorNode bootrom = new ProcessorNode(
                "rp2040.bootrom",
                ProcessorKind.BOOT_ROM,
                Optional.of("ARMv6-M"),
                Optional.of("ARM:LE:32:v6M"),
                Optional.of("default"),
                "BOOT_ROM",
                domain,
                "rp2040",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.ROM,
                Confidence.VERIFIED,
                List.of(romEvidence));

        ProcessorNode pio0 = new ProcessorNode(
                "rp2040.pio0",
                ProcessorKind.PROGRAMMABLE_COPROCESSOR,
                Optional.of("RP2040-PIO"),
                Optional.empty(),
                Optional.empty(),
                "COPROCESSOR",
                domain,
                "rp2040",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(pioEvidence));

        ProcessorNode pio1 = new ProcessorNode(
                "rp2040.pio1",
                ProcessorKind.PROGRAMMABLE_COPROCESSOR,
                Optional.of("RP2040-PIO"),
                Optional.empty(),
                Optional.empty(),
                "COPROCESSOR",
                domain,
                "rp2040",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(pioEvidence));

        SharedMemoryRegion sram = new SharedMemoryRegion(
                "rp2040.shared_sram",
                new AddressRange(ADDRESS_SPACE, 0x20000000L, 264 * 1024L),
                Set.of("rp2040.core0", "rp2040.core1"),
                Set.of("rp2040.core0", "rp2040.core1"),
                Set.of("rp2040.core0", "rp2040.core1"),
                List.of(),
                Confidence.VERIFIED,
                List.of(coreEvidence));

        BootRelationship bootRel = new BootRelationship(
                "rp2040.core0_launches_core1",
                "rp2040.core0",
                "rp2040.core1",
                BootRelationshipType.RELEASES_FROM_RESET,
                "Core 0 releases Core 1 from sleep/reset via SIO FIFO handshake",
                Confidence.VERIFIED,
                List.of(coreEvidence));

        InterProcessorLink mailbox = new InterProcessorLink(
                "rp2040.sio_fifo",
                CommunicationKind.FIFO,
                Set.of("rp2040.core0", "rp2040.core1"),
                Optional.of(new AddressRange(ADDRESS_SPACE, 0xD0000050L, 0x14L)),
                Confidence.VERIFIED,
                List.of(coreEvidence));

        InterProcessorLink spinlocks = new InterProcessorLink(
                "rp2040.sio_spinlocks",
                CommunicationKind.HARDWARE_SEMAPHORE,
                Set.of("rp2040.core0", "rp2040.core1"),
                Optional.of(new AddressRange(ADDRESS_SPACE, 0xD0000100L, 0x80L)),
                Confidence.VERIFIED,
                List.of(coreEvidence));

        InterProcessorLink pio0Irq = new InterProcessorLink(
                "rp2040.pio0_interrupts",
                CommunicationKind.FIFO,
                Set.of("rp2040.core0", "rp2040.core1", "rp2040.pio0"),
                Optional.of(new AddressRange(ADDRESS_SPACE, RpPioBlock.PIO0_BASE, 0x1000L)),
                Confidence.VERIFIED,
                List.of(pioEvidence));

        InterProcessorLink pio1Irq = new InterProcessorLink(
                "rp2040.pio1_interrupts",
                CommunicationKind.FIFO,
                Set.of("rp2040.core0", "rp2040.core1", "rp2040.pio1"),
                Optional.of(new AddressRange(ADDRESS_SPACE, RpPioBlock.PIO1_BASE, 0x1000L)),
                Confidence.VERIFIED,
                List.of(pioEvidence));

        ProcessorGroup group = new ProcessorGroup(
                "rp2040.symmetric_multicore",
                ProcessorGroupKind.SYMMETRIC,
                Set.of("rp2040.core0", "rp2040.core1"));

        return new ExecutionTopology(
                List.of(core0, core1, bootrom, pio0, pio1),
                List.of(sram),
                List.of(bootRel),
                List.of(mailbox, spinlocks, pio0Irq, pio1Irq),
                List.of(group),
                ProgramStrategy.SHARED_PROGRAM);
    }

    public List<RpPioBlock> pioBlocks() {
        return List.of(RpPioBlock.pio0(), RpPioBlock.pio1());
    }

    public String ghidraLanguageId() {
        return "ARM:LE:32:Cortex";
    }

    public String ghidraCompilerSpec() {
        return "default";
    }
}
