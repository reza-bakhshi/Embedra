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
 * Pure target provider for the dual Cortex-M33 / Hazard3 RISC-V Raspberry Pi RP2350/RP2354 family.
 */
public final class Rp2350TargetProvider implements RpTargetProvider {

    public static final String PROVIDER_ID = "raspberrypi.rp2350";

    public static final String ARCH_ARM = "ARM_CORTEX_M33";

    public static final String ARCH_RISCV = "HAZARD3_RISCV";

    public static final String ADDRESS_SPACE = "default";

    private final RpSiliconRecord silicon;

    public Rp2350TargetProvider(RpSiliconRecord silicon) {
        this.silicon = Objects.requireNonNull(silicon, "silicon must not be null");
        if (!silicon.exactPart().startsWith("RP2350") && !silicon.exactPart().startsWith("RP2354")) {
            throw new IllegalArgumentException(
                    "Rp2350TargetProvider requires RP2350 or RP2354 silicon record: " + silicon.exactPart());
        }
    }

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public String series() {
        return silicon.series();
    }

    @Override
    public RpSiliconRecord siliconRecord() {
        return silicon;
    }

    @Override
    public LanguageSelection selectLanguage(String bootArchitecture) {
        boolean isRiscV = ARCH_RISCV.equalsIgnoreCase(bootArchitecture);
        if (isRiscV) {
            Evidence evidence = new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "rp2350-datasheet",
                    "RP2350 Datasheet Chapter 2: Dual Hazard3 RV32IMAC RISC-V processors");
            return new LanguageSelection(
                    "RISCV:LE:32:default",
                    "default",
                    "RV32IMAC",
                    32,
                    2,
                    "little",
                    List.of(evidence));
        }

        // Default to ARM Cortex-M33
        Evidence evidence = new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "rp2350-datasheet",
                "RP2350 Datasheet Chapter 2: Dual ARM Cortex-M33 processors running ARMv8-M Mainline with TrustZone");
        return new LanguageSelection(
                "ARM:LE:32:v8M",
                "default",
                "ARMv8-M",
                32,
                2,
                "little",
                List.of(evidence));
    }

    @Override
    public List<RpMemoryRegion> memoryRegions(RpBoardProfile boardProfile) {
        long flashBytes;
        if (silicon.hasInternalFlash()) {
            flashBytes = silicon.internalFlashBytes();
        } else if (boardProfile != null) {
            flashBytes = boardProfile.externalFlashBytes();
        } else {
            flashBytes = 4 * 1024 * 1024L; // Default 4 MiB on Pico 2
        }

        List<RpMemoryRegion> regions = new ArrayList<>();

        // Boot ROM (32 KiB)
        regions.add(new RpMemoryRegion(
                "BOOT_ROM", RpMemoryRegionKind.BOOT_ROM,
                new AddressRange(ADDRESS_SPACE, 0x00000000L, 0x8000L),
                true, false, true, "RP2350 Internal Secure Boot ROM (32 KiB)"));

        // Flash XIP (internal stacked or external QMI)
        RpMemoryRegionKind flashKind = silicon.hasInternalFlash()
                ? RpMemoryRegionKind.INTERNAL_FLASH
                : RpMemoryRegionKind.FLASH_XIP;
        String flashDesc = silicon.hasInternalFlash()
                ? "RP2354 Stacked QSPI Internal Flash (2 MiB)"
                : "QMI Flash Execute-In-Place Window (" + (flashBytes / (1024 * 1024)) + " MiB)";
        regions.add(new RpMemoryRegion(
                "FLASH", flashKind,
                new AddressRange(ADDRESS_SPACE, 0x10000000L, flashBytes),
                true, false, true, flashDesc));

        // External PSRAM window (0x11000000 - 0x11FFFFFF, 16 MiB)
        regions.add(new RpMemoryRegion(
                "PSRAM", RpMemoryRegionKind.PSRAM,
                new AddressRange(ADDRESS_SPACE, 0x11000000L, 16 * 1024 * 1024L),
                true, true, true, "QMI PSRAM Execute-In-Place Window (16 MiB max)"));

        // SRAM (520 KiB total: 8 striped 64K banks + 2 non-striped 4K banks)
        regions.add(new RpMemoryRegion(
                "SRAM", RpMemoryRegionKind.SRAM,
                new AddressRange(ADDRESS_SPACE, 0x20000000L, 520 * 1024L),
                true, true, true, "SRAM Banks 0-9 (520 KiB total: striped 512 KiB + 2x 4 KiB)"));

        // Non-striped SRAM Direct Access (8 KiB)
        regions.add(new RpMemoryRegion(
                "NON_STRIPED_SRAM", RpMemoryRegionKind.SRAM,
                new AddressRange(ADDRESS_SPACE, 0x20080000L, 8 * 1024L),
                true, true, true, "Non-Striped SRAM Banks 8-9 Direct Access (8 KiB)"));

        // Peripherals (0x40000000 - 0x400FFFFF, 1 MiB)
        regions.add(new RpMemoryRegion(
                "PERIPHERALS", RpMemoryRegionKind.PERIPHERALS,
                new AddressRange(ADDRESS_SPACE, 0x40000000L, 0x100000L),
                true, true, false, "RP2350 Hardware Peripherals"));

        // OTP Memory (8 KiB at 0x40130000)
        regions.add(new RpMemoryRegion(
                "OTP", RpMemoryRegionKind.OTP,
                new AddressRange(ADDRESS_SPACE, 0x40130000L, 0x2000L),
                true, false, false, "RP2350 8 KiB One-Time Programmable (OTP) Memory"));

        // Atomic Aliases (0x50000000 - 0x500FFFFF, 1 MiB)
        regions.add(new RpMemoryRegion(
                "ATOMIC_ALIASES", RpMemoryRegionKind.ATOMIC_ALIASES,
                new AddressRange(ADDRESS_SPACE, 0x50000000L, 0x100000L),
                true, true, false, "RP2350 Atomic Register Access Aliases"));

        // SIO (Single-cycle IO)
        regions.add(new RpMemoryRegion(
                "SIO", RpMemoryRegionKind.SIO,
                new AddressRange(ADDRESS_SPACE, 0xD0000000L, 0x180L),
                true, true, false, "RP2350 Single-Cycle IO (FIFOs, Spinlocks, Dividers)"));

        // PPB (Private Peripheral Bus / Cortex-M33 SCS)
        regions.add(new RpMemoryRegion(
                "PPB", RpMemoryRegionKind.PPB,
                new AddressRange(ADDRESS_SPACE, 0xE0000000L, 0x100000L),
                true, true, false, "Cortex-M33 System Control Space (NVIC, SAU, MPU)"));

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
        boolean isRiscV = ARCH_RISCV.equalsIgnoreCase(bootArchitecture);
        String isa = isRiscV ? "RV32IMAC" : "ARMv8-M";
        String langId = isRiscV ? "RISCV:LE:32:default" : "ARM:LE:32:v8M";
        SecurityDomain domain = isRiscV
                ? new SecurityDomain("rp2350.domain", SecurityDomainKind.NON_SECURE)
                : new SecurityDomain("rp2350.trustzone_secure", SecurityDomainKind.SECURE);

        Evidence coreEvidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD, "rp2350-core",
                "RP2350 symmetric dual-core " + (isRiscV ? "Hazard3 RISC-V" : "Cortex-M33"));
        Evidence pioEvidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD, "rp2350-pio",
                "RP2350 three PIO blocks with 4 state machines each (12 SMs total)");
        Evidence romEvidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD, "rp2350-rom",
                "RP2350 internal 32 KiB Secure Boot ROM");
        Evidence cryptoEvidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD, "rp2350-crypto",
                "RP2350 hardware cryptographic accelerators (SHA-256 and TRNG)");

        ProcessorNode core0 = new ProcessorNode(
                "rp2350.core0",
                ProcessorKind.CPU_CORE,
                Optional.of(isa),
                Optional.of(langId),
                Optional.of("default"),
                "BOOT_CORE",
                domain,
                "rp2350",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(coreEvidence));

        ProcessorNode core1 = new ProcessorNode(
                "rp2350.core1",
                ProcessorKind.CPU_CORE,
                Optional.of(isa),
                Optional.of(langId),
                Optional.of("default"),
                "SECONDARY_CORE",
                domain,
                "rp2350",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(coreEvidence));

        ProcessorNode bootrom = new ProcessorNode(
                "rp2350.bootrom",
                ProcessorKind.BOOT_ROM,
                Optional.of(isa),
                Optional.of(langId),
                Optional.of("default"),
                "BOOT_ROM",
                domain,
                "rp2350",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.ROM,
                Confidence.VERIFIED,
                List.of(romEvidence));

        ProcessorNode pio0 = new ProcessorNode(
                "rp2350.pio0",
                ProcessorKind.PROGRAMMABLE_COPROCESSOR,
                Optional.of("RP2350-PIO"),
                Optional.empty(),
                Optional.empty(),
                "COPROCESSOR",
                domain,
                "rp2350",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(pioEvidence));

        ProcessorNode pio1 = new ProcessorNode(
                "rp2350.pio1",
                ProcessorKind.PROGRAMMABLE_COPROCESSOR,
                Optional.of("RP2350-PIO"),
                Optional.empty(),
                Optional.empty(),
                "COPROCESSOR",
                domain,
                "rp2350",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(pioEvidence));

        ProcessorNode pio2 = new ProcessorNode(
                "rp2350.pio2",
                ProcessorKind.PROGRAMMABLE_COPROCESSOR,
                Optional.of("RP2350-PIO"),
                Optional.empty(),
                Optional.empty(),
                "COPROCESSOR",
                domain,
                "rp2350",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(pioEvidence));

        ProcessorNode sha256 = new ProcessorNode(
                "rp2350.sha256",
                ProcessorKind.FIXED_FUNCTION_ACCELERATOR,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                "ACCELERATOR",
                domain,
                "rp2350",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(cryptoEvidence));

        ProcessorNode trng = new ProcessorNode(
                "rp2350.trng",
                ProcessorKind.FIXED_FUNCTION_ACCELERATOR,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                "ACCELERATOR",
                domain,
                "rp2350",
                Set.of(ADDRESS_SPACE),
                List.of(),
                FirmwareSource.SHARED_IMAGE,
                Confidence.VERIFIED,
                List.of(cryptoEvidence));

        SharedMemoryRegion sram = new SharedMemoryRegion(
                "rp2350.shared_sram",
                new AddressRange(ADDRESS_SPACE, 0x20000000L, 520 * 1024L),
                Set.of("rp2350.core0", "rp2350.core1"),
                Set.of("rp2350.core0", "rp2350.core1"),
                Set.of("rp2350.core0", "rp2350.core1"),
                List.of(),
                Confidence.VERIFIED,
                List.of(coreEvidence));

        SharedMemoryRegion otp = new SharedMemoryRegion(
                "rp2350.shared_otp",
                new AddressRange(ADDRESS_SPACE, Rp2350OtpMemory.OTP_BASE, Rp2350OtpMemory.OTP_SIZE_BYTES),
                Set.of("rp2350.core0", "rp2350.core1", "rp2350.bootrom"),
                Set.of("rp2350.core0", "rp2350.core1", "rp2350.bootrom"),
                Set.of("rp2350.core0", "rp2350.core1", "rp2350.bootrom"),
                List.of(),
                Confidence.VERIFIED,
                List.of(cryptoEvidence));

        BootRelationship bootRel = new BootRelationship(
                "rp2350.core0_launches_core1",
                "rp2350.core0",
                "rp2350.core1",
                BootRelationshipType.RELEASES_FROM_RESET,
                "Core 0 releases Core 1 from sleep/reset via SIO FIFO handshake",
                Confidence.VERIFIED,
                List.of(coreEvidence));

        InterProcessorLink mailbox = new InterProcessorLink(
                "rp2350.sio_fifo",
                CommunicationKind.FIFO,
                Set.of("rp2350.core0", "rp2350.core1"),
                Optional.of(new AddressRange(ADDRESS_SPACE, 0xD0000050L, 0x14L)),
                Confidence.VERIFIED,
                List.of(coreEvidence));

        InterProcessorLink spinlocks = new InterProcessorLink(
                "rp2350.sio_spinlocks",
                CommunicationKind.HARDWARE_SEMAPHORE,
                Set.of("rp2350.core0", "rp2350.core1"),
                Optional.of(new AddressRange(ADDRESS_SPACE, 0xD0000100L, 0x80L)),
                Confidence.VERIFIED,
                List.of(coreEvidence));

        InterProcessorLink pio0Irq = new InterProcessorLink(
                "rp2350.pio0_interrupts",
                CommunicationKind.FIFO,
                Set.of("rp2350.core0", "rp2350.core1", "rp2350.pio0"),
                Optional.of(new AddressRange(ADDRESS_SPACE, RpPioBlock.PIO0_BASE, 0x1000L)),
                Confidence.VERIFIED,
                List.of(pioEvidence));

        InterProcessorLink pio1Irq = new InterProcessorLink(
                "rp2350.pio1_interrupts",
                CommunicationKind.FIFO,
                Set.of("rp2350.core0", "rp2350.core1", "rp2350.pio1"),
                Optional.of(new AddressRange(ADDRESS_SPACE, RpPioBlock.PIO1_BASE, 0x1000L)),
                Confidence.VERIFIED,
                List.of(pioEvidence));

        InterProcessorLink pio2Irq = new InterProcessorLink(
                "rp2350.pio2_interrupts",
                CommunicationKind.FIFO,
                Set.of("rp2350.core0", "rp2350.core1", "rp2350.pio2"),
                Optional.of(new AddressRange(ADDRESS_SPACE, RpPioBlock.PIO2_BASE, 0x1000L)),
                Confidence.VERIFIED,
                List.of(pioEvidence));

        ProcessorGroup group = new ProcessorGroup(
                "rp2350.multicore_cluster",
                ProcessorGroupKind.SYMMETRIC,
                Set.of("rp2350.core0", "rp2350.core1"));

        return new ExecutionTopology(
                List.of(core0, core1, bootrom, pio0, pio1, pio2, sha256, trng),
                List.of(sram, otp),
                List.of(bootRel),
                List.of(mailbox, spinlocks, pio0Irq, pio1Irq, pio2Irq),
                List.of(group),
                ProgramStrategy.SHARED_PROGRAM);
    }

    public List<RpPioBlock> pioBlocks() {
        return List.of(RpPioBlock.pio0(), RpPioBlock.pio1(), RpPioBlock.pio2());
    }

    public String ghidraLanguageId(String bootArchitecture) {
        return ARCH_RISCV.equalsIgnoreCase(bootArchitecture) ? "RISCV:LE:32:default" : "ARM:LE:32:v8-m";
    }

    public String ghidraCompilerSpec(String bootArchitecture) {
        return ARCH_RISCV.equalsIgnoreCase(bootArchitecture) ? "gcc" : "default";
    }

    public int gpioCount() {
        return silicon.exactPart().endsWith("A") ? 30 : 48;
    }
}
