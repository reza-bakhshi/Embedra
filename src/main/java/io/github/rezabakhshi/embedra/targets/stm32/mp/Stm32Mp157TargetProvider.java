package io.github.rezabakhshi.embedra.targets.stm32.mp;

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
import io.github.rezabakhshi.embedra.core.model.ResetEntry;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.core.model.SecurityDomainKind;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Target provider for the STM32MP157 heterogeneous microprocessor series.
 *
 * <p>Features dual Cortex-A7 32-bit application processors and a Cortex-M4
 * 32-bit real-time coprocessor. Sourced from BSD-3-Clause ST open pin data,
 * upstream Linux devicetree (stm32mp157c.dtsi), TF-A, and OpenOCD scripts.</p>
 */
public final class Stm32Mp157TargetProvider implements Stm32MpTargetProvider {
    public static final String PROVIDER_ID =
        "io.github.rezabakhshi.embedra.targets.stm32.mp.stm32mp157";

    public static final String PROVIDER_VERSION = "1.0.0";

    public static final String EXACT_PART = "STM32MP157C";

    public static final String LINE = "STM32MP157";

    public static final String FAMILY = "STM32MP1";

    private static final Set<String> MATCH_KEYS = Set.of(
        "STM32MP157", "STM32MP157A", "STM32MP157C", "STM32MP157D", "STM32MP157F",
        "STM32MP157AAA3", "STM32MP157CAA3", "STM32MP157CAC3", "STM32MP157FAC3"
    );

    private final List<Evidence> providerEvidence = List.of(
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "STMicroelectronics RM0436",
            "STM32MP157 Reference Manual RM0436"),
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "Linux kernel stm32mp157c.dtsi",
            "arch/arm/boot/dts/st/stm32mp157c.dtsi (GPL-2.0+ OR BSD-3-Clause)"),
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "ARM Trusted Firmware-A",
            "stm32mp1 platform port (BSD-3-Clause)")
    );

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public String providerVersion() {
        return PROVIDER_VERSION;
    }

    @Override
    public String exactPart() {
        return EXACT_PART;
    }

    @Override
    public String line() {
        return LINE;
    }

    @Override
    public String family() {
        return FAMILY;
    }

    @Override
    public Confidence confidence() {
        return Confidence.VERIFIED;
    }

    @Override
    public List<Evidence> evidence() {
        return providerEvidence;
    }

    @Override
    public boolean matches(String exactPartOrLine) {
        if (exactPartOrLine == null || exactPartOrLine.isBlank()) {
            return false;
        }
        String normalized = exactPartOrLine.trim().toUpperCase(Locale.ROOT);
        return MATCH_KEYS.contains(normalized) || normalized.startsWith("STM32MP157");
    }

    @Override
    public SupportDecision supports(String exactPartOrLine) {
        if (matches(exactPartOrLine)) {
            return new SupportDecision(true, Optional.of(exactPart()),
                "STM32MP157 dual Cortex-A7 plus Cortex-M4 heterogeneous processor",
                providerEvidence);
        }
        return new SupportDecision(false, Optional.empty(),
            "Not matched by STM32MP157 provider",
            List.of());
    }

    @Override
    public ExecutionTopology topology() {
        SecurityDomain nonSecure = SecurityDomain.nonSecure();
        SecurityDomain secure = SecurityDomain.secure();

        ProcessorNode ca7_0 = new ProcessorNode(
            "ca7_0",
            ProcessorKind.CPU_CORE,
            Optional.of("ARMv7-A"),
            Optional.of("ARM:LE:32:v7"),
            Optional.of("default"),
            "APPLICATION",
            nonSecure,
            "ca7_0",
            Set.of("ram", "rom"),
            List.of(new ResetEntry("ca7_0_reset", "ram", 0xC2000000L, Confidence.DERIVED, providerEvidence)),
            FirmwareSource.SHARED_IMAGE,
            Confidence.VERIFIED,
            providerEvidence
        );

        ProcessorNode ca7_1 = new ProcessorNode(
            "ca7_1",
            ProcessorKind.CPU_CORE,
            Optional.of("ARMv7-A"),
            Optional.of("ARM:LE:32:v7"),
            Optional.of("default"),
            "APPLICATION",
            nonSecure,
            "ca7_1",
            Set.of("ram", "rom"),
            List.of(),
            FirmwareSource.SHARED_IMAGE,
            Confidence.VERIFIED,
            providerEvidence
        );

        ProcessorNode cm4 = new ProcessorNode(
            "cm4",
            ProcessorKind.CPU_CORE,
            Optional.of("ARMv7E-M"),
            Optional.of("ARM:LE:32:Cortex"),
            Optional.of("default"),
            "MICROCONTROLLER",
            nonSecure,
            "cm4",
            Set.of("ram", "rom"),
            List.of(new ResetEntry("cm4_reset", "ram", 0x10000000L, Confidence.DERIVED, providerEvidence)),
            FirmwareSource.INDEPENDENT_IMAGE,
            Confidence.VERIFIED,
            providerEvidence
        );

        ProcessorNode bootrom = new ProcessorNode(
            "bootrom",
            ProcessorKind.BOOT_ROM,
            Optional.of("ARMv7-A"),
            Optional.of("ARM:LE:32:v7"),
            Optional.of("default"),
            "BOOT_ROM",
            secure,
            "system",
            Set.of("rom"),
            List.of(new ResetEntry("bootrom_reset", "rom", 0x00000000L, Confidence.VERIFIED, providerEvidence)),
            FirmwareSource.ROM,
            Confidence.VERIFIED,
            providerEvidence
        );

        List<SharedMemoryRegion> sharedMemories = List.of(
            new SharedMemoryRegion(
                "sysram",
                new AddressRange("ram", 0x2FFC0000L, 0x40000L),
                Set.of("ca7_0"),
                Set.of("ca7_0", "ca7_1", "cm4"),
                Set.of("ca7_0", "ca7_1", "cm4"),
                List.of(),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new SharedMemoryRegion(
                "mcuram",
                new AddressRange("ram", 0x10000000L, 0x60000L),
                Set.of("cm4"),
                Set.of("ca7_0", "ca7_1", "cm4"),
                Set.of("ca7_0", "ca7_1", "cm4"),
                List.of(new AddressRange("ram", 0x30000000L, 0x60000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new SharedMemoryRegion(
                "retram",
                new AddressRange("ram", 0x00000000L, 0x10000L),
                Set.of("cm4"),
                Set.of("ca7_0", "cm4"),
                Set.of("ca7_0", "cm4"),
                List.of(new AddressRange("ram", 0x38000000L, 0x10000L)),
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<BootRelationship> bootRelations = List.of(
            new BootRelationship(
                "bootrom_releases_ca7",
                "bootrom",
                "ca7_0",
                BootRelationshipType.RELEASES_FROM_RESET,
                "SoC reset vector execution jumps to FSBL and releases primary application core",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new BootRelationship(
                "ca7_releases_cm4",
                "ca7_0",
                "cm4",
                BootRelationshipType.RELEASES_FROM_RESET,
                "Linux remoteproc unresets Cortex-M4 via RCC and mailbox kick",
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<InterProcessorLink> commLinks = List.of(
            new InterProcessorLink(
                "ipcc_mailbox",
                CommunicationKind.MAILBOX,
                Set.of("ca7_0", "cm4"),
                Optional.of(new AddressRange("periph", 0x5C001000L, 0x400L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new InterProcessorLink(
                "hsem_semaphore",
                CommunicationKind.HARDWARE_SEMAPHORE,
                Set.of("ca7_0", "cm4"),
                Optional.of(new AddressRange("periph", 0x5C000000L, 0x400L)),
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<ProcessorGroup> groups = List.of(
            new ProcessorGroup(
                "ca7_cluster",
                ProcessorGroupKind.SYMMETRIC,
                Set.of("ca7_0", "ca7_1")
            )
        );

        return new ExecutionTopology(
            List.of(ca7_0, ca7_1, cm4, bootrom),
            sharedMemories,
            bootRelations,
            commLinks,
            groups,
            ProgramStrategy.SEPARATE_PROGRAMS
        );
    }

    @Override
    public Stm32MpBootChainPlan bootChainPlan() {
        return bootChainPlan(Stm32MpBootChainPlan.BootArchitecture.A7_SECURE_BOOT);
    }

    @Override
    public Stm32MpBootChainPlan bootChainPlan(Stm32MpBootChainPlan.BootArchitecture architecture) {
        Objects.requireNonNull(architecture, "architecture");
        SecurityDomain secure = SecurityDomain.secure();
        SecurityDomain nonSecure = SecurityDomain.nonSecure();

        List<Stm32MpBootChainPlan.BootStage> stages = List.of(
            new Stm32MpBootChainPlan.BootStage(
                "stage_rom",
                Stm32MpBootChainPlan.StageKind.ROM,
                "bootrom",
                "BootROM",
                "Masked internal ROM code authenticating FSBL",
                secure,
                Optional.of(new AddressRange("rom", 0x00000000L, 0x20000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_fsbl",
                Stm32MpBootChainPlan.StageKind.FSBL,
                "ca7_0",
                "TF-A BL2",
                "First Stage Bootloader (TF-A BL2) executing in SYSRAM, initializing clocks and DDR",
                secure,
                Optional.of(new AddressRange("ram", 0x2FFC0000L, 0x20000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_secure_os",
                Stm32MpBootChainPlan.StageKind.SECURE_OS,
                "ca7_0",
                "OP-TEE",
                "Trusted Execution Environment (OP-TEE BL32) in secure RAM",
                secure,
                Optional.of(new AddressRange("ram", 0x2FFE0000L, 0x20000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_ssbl",
                Stm32MpBootChainPlan.StageKind.SSBL,
                "ca7_0",
                "U-Boot",
                "Second Stage Bootloader (U-Boot BL33) executing in external DDR RAM",
                nonSecure,
                Optional.of(new AddressRange("ram", 0xC0100000L, 0x100000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_os",
                Stm32MpBootChainPlan.StageKind.NON_SECURE_OS,
                "ca7_0",
                "Linux Kernel",
                "Linux Operating System running on Cortex-A7 in non-secure DDR",
                nonSecure,
                Optional.of(new AddressRange("ram", 0xC2000000L, 0x2000000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_coprocessor",
                Stm32MpBootChainPlan.StageKind.COPROCESSOR_FIRMWARE,
                "cm4",
                "Cortex-M4 Firmware",
                "Cortex-M4 real-time firmware loaded into MCU SRAM via remoteproc",
                nonSecure,
                Optional.of(new AddressRange("ram", 0x10000000L, 0x40000L)),
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        return new Stm32MpBootChainPlan(
            exactPart(),
            Stm32MpBootChainPlan.BootArchitecture.A7_SECURE_BOOT,
            stages,
            Confidence.VERIFIED,
            providerEvidence
        );
    }

    @Override
    public Stm32MpDeviceTreePlan deviceTreePlan() {
        Stm32MpDeviceTreePlan.RemoteProcNode rproc = new Stm32MpDeviceTreePlan.RemoteProcNode(
            "m4_rproc",
            "cm4",
            List.of("retram", "mcuram", "mcuram2", "vdev0vring0", "vdev0vring1", "vdev0buffer"),
            List.of(
                new Stm32MpDeviceTreePlan.MailboxChannel("vq0", "ipcc", 0),
                new Stm32MpDeviceTreePlan.MailboxChannel("vq1", "ipcc", 1),
                new Stm32MpDeviceTreePlan.MailboxChannel("shutdown", "ipcc", 2)
            ),
            Optional.of("hsem"),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpDeviceTreePlan.MailboxBinding ipcc = new Stm32MpDeviceTreePlan.MailboxBinding(
            "ipcc",
            new AddressRange("periph", 0x5C001000L, 0x400L),
            2,
            List.of("rx", "tx"),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpDeviceTreePlan.SemaphoreBinding hsem = new Stm32MpDeviceTreePlan.SemaphoreBinding(
            "hsem",
            new AddressRange("periph", 0x5C000000L, 0x400L),
            32,
            Confidence.VERIFIED,
            providerEvidence
        );

        List<Stm32MpDeviceTreePlan.ReservedMemoryNode> reserved = List.of(
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("mcuram",
                new AddressRange("ram", 0x30000000L, 0x20000L), true, "coprocessor-code",
                Confidence.VERIFIED, providerEvidence),
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("mcuram2",
                new AddressRange("ram", 0x30020000L, 0x20000L), true, "coprocessor-data",
                Confidence.VERIFIED, providerEvidence),
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("retram",
                new AddressRange("ram", 0x38000000L, 0x10000L), true, "coprocessor-vectors",
                Confidence.VERIFIED, providerEvidence),
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("vdev0vring0",
                new AddressRange("ram", 0x10040000L, 0x1000L), true, "rpmsg-vring0",
                Confidence.VERIFIED, providerEvidence),
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("vdev0vring1",
                new AddressRange("ram", 0x10041000L, 0x1000L), true, "rpmsg-vring1",
                Confidence.VERIFIED, providerEvidence),
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("vdev0buffer",
                new AddressRange("ram", 0x10042000L, 0x2000L), true, "rpmsg-buffers",
                Confidence.VERIFIED, providerEvidence)
        );

        return new Stm32MpDeviceTreePlan(
            exactPart(),
            "arch/arm/boot/dts/st/stm32mp157c.dtsi",
            "(GPL-2.0+ OR BSD-3-Clause)",
            List.of(rproc),
            List.of(ipcc),
            List.of(hsem),
            reserved,
            Confidence.VERIFIED,
            providerEvidence
        );
    }

    @Override
    public Stm32MpSecurityPlan securityPlan() {
        SecurityDomain secure = SecurityDomain.secure();
        SecurityDomain nonSecure = SecurityDomain.nonSecure();

        List<Stm32MpSecurityPlan.SecurityFirewallWindow> windows = List.of(
            new Stm32MpSecurityPlan.SecurityFirewallWindow(
                "etzpc_controller",
                "ETZPC",
                new AddressRange("periph", 0x5C007000L, 0x400L),
                secure,
                true,
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<Stm32MpSecurityPlan.OtpSecurityRegion> otp = List.of(
            new Stm32MpSecurityPlan.OtpSecurityRegion(
                "bsec_otp",
                "BSEC",
                new AddressRange("periph", 0x5C005000L, 0x400L),
                true,
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        return new Stm32MpSecurityPlan(
            exactPart(),
            Stm32MpSecurityPlan.SecurityArchitecture.ETZPC_TRUSTZONE,
            List.of(secure, nonSecure),
            windows,
            otp,
            Confidence.VERIFIED,
            providerEvidence
        );
    }

    @Override
    public Stm32MpSharedResourcesPlan sharedResourcesPlan() {
        return new Stm32MpSharedResourcesPlan(
            exactPart(),
            topology().sharedMemories(),
            topology().communicationLinks(),
            Confidence.VERIFIED,
            providerEvidence
        );
    }

    @Override
    public Stm32MpWorkspacePlan workspacePlan() {
        SecurityDomain nonSecure = SecurityDomain.nonSecure();
        SecurityDomain secure = SecurityDomain.secure();

        Stm32MpWorkspacePlan.ProgramSlot linux = new Stm32MpWorkspacePlan.ProgramSlot(
            "ca7-linux-program",
            "ca7_0",
            "Linux Non-Secure OS",
            FirmwareSource.SHARED_IMAGE,
            "ARMv7-A",
            "ARM:LE:32:v7",
            "default",
            nonSecure,
            Optional.of(new AddressRange("ram", 0xC2000000L, 0x2000000L)),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpWorkspacePlan.ProgramSlot secureSlot = new Stm32MpWorkspacePlan.ProgramSlot(
            "ca7-secure-program",
            "ca7_0",
            "TF-A and OP-TEE Secure World",
            FirmwareSource.SHARED_IMAGE,
            "ARMv7-A",
            "ARM:LE:32:v7",
            "default",
            secure,
            Optional.of(new AddressRange("ram", 0x2FFC0000L, 0x40000L)),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpWorkspacePlan.ProgramSlot m4 = new Stm32MpWorkspacePlan.ProgramSlot(
            "cm4-firmware-program",
            "cm4",
            "Cortex-M4 Real-Time Firmware",
            FirmwareSource.INDEPENDENT_IMAGE,
            "ARMv7E-M",
            "ARM:LE:32:Cortex",
            "default",
            nonSecure,
            Optional.of(new AddressRange("ram", 0x10000000L, 0x40000L)),
            Confidence.VERIFIED,
            providerEvidence
        );

        List<Stm32MpWorkspacePlan.CrossProgramReference> refs = List.of(
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "boot_handoff_tfa_to_linux",
                Stm32MpWorkspacePlan.ReferenceKind.BOOT_HANDOFF,
                "ca7-secure-program",
                "ca7-linux-program",
                Optional.empty(),
                "TF-A BL2 passes execution to U-Boot and Linux Kernel",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "boot_handoff_linux_to_m4",
                Stm32MpWorkspacePlan.ReferenceKind.BOOT_HANDOFF,
                "ca7-linux-program",
                "cm4-firmware-program",
                Optional.empty(),
                "Linux remoteproc releases Cortex-M4 from reset and kicks mailbox",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "shared_ipcc_mailbox",
                Stm32MpWorkspacePlan.ReferenceKind.SHARED_MAILBOX,
                "ca7-linux-program",
                "cm4-firmware-program",
                Optional.of(new AddressRange("periph", 0x5C001000L, 0x400L)),
                "IPCC hardware mailbox registers for RPMsg signaling",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "shared_hsem_spinlock",
                Stm32MpWorkspacePlan.ReferenceKind.SHARED_SEMAPHORE,
                "ca7-linux-program",
                "cm4-firmware-program",
                Optional.of(new AddressRange("periph", 0x5C000000L, 0x400L)),
                "HSEM hardware semaphore registers for shared peripheral arbitration",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "shared_mcuram",
                Stm32MpWorkspacePlan.ReferenceKind.SHARED_MEMORY,
                "ca7-linux-program",
                "cm4-firmware-program",
                Optional.of(new AddressRange("ram", 0x10000000L, 0x60000L)),
                "Shared MCU SRAM window (aliased at 0x30000000 for Cortex-A7)",
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        return new Stm32MpWorkspacePlan(
            exactPart(),
            List.of(linux, secureSlot, m4),
            refs,
            Confidence.VERIFIED,
            providerEvidence
        );
    }
}
