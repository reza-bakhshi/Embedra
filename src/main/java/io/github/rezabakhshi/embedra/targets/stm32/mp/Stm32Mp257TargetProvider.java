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
 * Target provider for the STM32MP257 64-bit heterogeneous microprocessor series.
 *
 * <p>Features dual 64-bit Cortex-A35 application processors, a 32-bit Cortex-M33
 * real-time coprocessor with TrustZone, and a Cortex-M0+ SmartRun ultra-low-power
 * core. Sourced from Apache-2.0 ST CMSIS headers (cmsis-device-mp2), upstream
 * Linux devicetree (stm32mp257.dtsi), TF-A, and OpenOCD scripts.</p>
 */
public final class Stm32Mp257TargetProvider implements Stm32MpTargetProvider {
    public static final String PROVIDER_ID =
        "io.github.rezabakhshi.embedra.targets.stm32.mp.stm32mp257";

    public static final String PROVIDER_VERSION = "1.0.0";

    public static final String EXACT_PART = "STM32MP257F";

    public static final String LINE = "STM32MP257";

    public static final String FAMILY = "STM32MP2";

    private static final Set<String> MATCH_KEYS = Set.of(
        "STM32MP257", "STM32MP257A", "STM32MP257C", "STM32MP257D", "STM32MP257F",
        "STM32MP257AAI3", "STM32MP257CAI3", "STM32MP257DAI3", "STM32MP257FAI3"
    );

    private final List<Evidence> providerEvidence = List.of(
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "STMicroelectronics RM0457",
            "STM32MP257 Reference Manual RM0457"),
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "ST CMSIS device headers",
            "cmsis-device-mp2 dbda522 (Apache-2.0)"),
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "Linux kernel stm32mp257.dtsi",
            "arch/arm64/boot/dts/st/stm32mp257.dtsi (GPL-2.0-or-later OR BSD-3-Clause)")
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
        return MATCH_KEYS.contains(normalized) || normalized.startsWith("STM32MP257");
    }

    @Override
    public SupportDecision supports(String exactPartOrLine) {
        if (matches(exactPartOrLine)) {
            return new SupportDecision(true, Optional.of(exactPart()),
                "STM32MP257 dual Cortex-A35 plus Cortex-M33 plus Cortex-M0+ heterogeneous processor",
                providerEvidence);
        }
        return new SupportDecision(false, Optional.empty(),
            "Not matched by STM32MP257 provider",
            List.of());
    }

    @Override
    public ExecutionTopology topology() {
        SecurityDomain nonSecure = SecurityDomain.nonSecure();
        SecurityDomain secure = SecurityDomain.secure();
        SecurityDomain smartRun = new SecurityDomain("smart-run", SecurityDomainKind.CUSTOM);

        ProcessorNode ca35_0 = new ProcessorNode(
            "ca35_0",
            ProcessorKind.CPU_CORE,
            Optional.of("AArch64"),
            Optional.of("AARCH64:LE:64:v8A"),
            Optional.of("default"),
            "APPLICATION",
            nonSecure,
            "ca35_0",
            Set.of("ram", "rom"),
            List.of(new ResetEntry("ca35_0_reset", "ram", 0x80000000L, Confidence.DERIVED, providerEvidence)),
            FirmwareSource.SHARED_IMAGE,
            Confidence.VERIFIED,
            providerEvidence
        );

        ProcessorNode ca35_1 = new ProcessorNode(
            "ca35_1",
            ProcessorKind.CPU_CORE,
            Optional.of("AArch64"),
            Optional.of("AARCH64:LE:64:v8A"),
            Optional.of("default"),
            "APPLICATION",
            nonSecure,
            "ca35_1",
            Set.of("ram", "rom"),
            List.of(),
            FirmwareSource.SHARED_IMAGE,
            Confidence.VERIFIED,
            providerEvidence
        );

        ProcessorNode cm33 = new ProcessorNode(
            "cm33",
            ProcessorKind.CPU_CORE,
            Optional.of("ARMv8-M"),
            Optional.of("ARM:LE:32:Cortex"),
            Optional.of("default"),
            "MICROCONTROLLER",
            nonSecure,
            "cm33",
            Set.of("ram", "rom"),
            List.of(new ResetEntry("cm33_reset", "ram", 0x0E000000L, Confidence.DERIVED, providerEvidence)),
            FirmwareSource.INDEPENDENT_IMAGE,
            Confidence.VERIFIED,
            providerEvidence
        );

        ProcessorNode cm0p = new ProcessorNode(
            "cm0p",
            ProcessorKind.CPU_CORE,
            Optional.of("ARMv6-M"),
            Optional.of("ARM:LE:32:v6M"),
            Optional.of("default"),
            "Low-Power SmartRun Core",
            smartRun,
            "cm0p",
            Set.of("ram"),
            List.of(),
            FirmwareSource.INDEPENDENT_IMAGE,
            Confidence.VERIFIED,
            providerEvidence
        );

        ProcessorNode bootrom = new ProcessorNode(
            "bootrom",
            ProcessorKind.BOOT_ROM,
            Optional.of("AArch64"),
            Optional.of("AARCH64:LE:64:v8A"),
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
                new AddressRange("ram", 0x0E000000L, 0x40000L),
                Set.of("ca35_0"),
                Set.of("ca35_0", "ca35_1", "cm33"),
                Set.of("ca35_0", "ca35_1", "cm33"),
                List.of(),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new SharedMemoryRegion(
                "smartrun_sram",
                new AddressRange("ram", 0x0E0C0000L, 0x8000L),
                Set.of("cm0p"),
                Set.of("ca35_0", "cm33", "cm0p"),
                Set.of("ca35_0", "cm33", "cm0p"),
                List.of(),
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<BootRelationship> bootRelations = List.of(
            new BootRelationship(
                "bootrom_releases_ca35",
                "bootrom",
                "ca35_0",
                BootRelationshipType.RELEASES_FROM_RESET,
                "A35-TD default boot: SoC ROM executes TF-A BL2 on primary Cortex-A35",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new BootRelationship(
                "ca35_releases_cm33",
                "ca35_0",
                "cm33",
                BootRelationshipType.RELEASES_FROM_RESET,
                "Linux remoteproc releases Cortex-M33 coprocessor from reset",
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<InterProcessorLink> commLinks = List.of(
            new InterProcessorLink(
                "ipcc_mailbox",
                CommunicationKind.MAILBOX,
                Set.of("ca35_0", "cm33"),
                Optional.of(new AddressRange("periph", 0x46230000L, 0x400L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new InterProcessorLink(
                "hsem_semaphore",
                CommunicationKind.HARDWARE_SEMAPHORE,
                Set.of("ca35_0", "cm33"),
                Optional.of(new AddressRange("periph", 0x46220000L, 0x400L)),
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<ProcessorGroup> groups = List.of(
            new ProcessorGroup(
                "ca35_cluster",
                ProcessorGroupKind.SYMMETRIC,
                Set.of("ca35_0", "ca35_1")
            )
        );

        return new ExecutionTopology(
            List.of(ca35_0, ca35_1, cm33, cm0p, bootrom),
            sharedMemories,
            bootRelations,
            commLinks,
            groups,
            ProgramStrategy.SEPARATE_PROGRAMS
        );
    }

    @Override
    public Stm32MpBootChainPlan bootChainPlan() {
        return bootChainPlan(Stm32MpBootChainPlan.BootArchitecture.A35_TRUSTED_DOMAIN);
    }

    @Override
    public Stm32MpBootChainPlan bootChainPlan(Stm32MpBootChainPlan.BootArchitecture architecture) {
        Objects.requireNonNull(architecture, "architecture");
        SecurityDomain secure = SecurityDomain.secure();
        SecurityDomain nonSecure = SecurityDomain.nonSecure();

        if (architecture == Stm32MpBootChainPlan.BootArchitecture.M33_TRUSTED_DOMAIN) {
            List<Stm32MpBootChainPlan.BootStage> m33Stages = List.of(
                new Stm32MpBootChainPlan.BootStage(
                    "stage_rom_m33",
                    Stm32MpBootChainPlan.StageKind.ROM,
                    "cm33",
                    "BootROM M33",
                    "ROM Code initializes system and executes Secure FSBL on Cortex-M33",
                    secure,
                    Optional.of(new AddressRange("rom", 0x00000000L, 0x20000L)),
                    Confidence.VERIFIED,
                    providerEvidence
                ),
                new Stm32MpBootChainPlan.BootStage(
                    "stage_m33_fsbl",
                    Stm32MpBootChainPlan.StageKind.FSBL,
                    "cm33",
                    "M33 FSBL",
                    "Cortex-M33 First Stage Bootloader in SYSRAM, configuring clocks and DDR",
                    secure,
                    Optional.of(new AddressRange("ram", 0x0E000000L, 0x20000L)),
                    Confidence.VERIFIED,
                    providerEvidence
                ),
                new Stm32MpBootChainPlan.BootStage(
                    "stage_a35_ssbl",
                    Stm32MpBootChainPlan.StageKind.SSBL,
                    "ca35_0",
                    "U-Boot",
                    "U-Boot SSBL released by M33 to boot Linux on Cortex-A35",
                    nonSecure,
                    Optional.of(new AddressRange("ram", 0x80000000L, 0x100000L)),
                    Confidence.VERIFIED,
                    providerEvidence
                )
            );
            return new Stm32MpBootChainPlan(
                exactPart(),
                Stm32MpBootChainPlan.BootArchitecture.M33_TRUSTED_DOMAIN,
                m33Stages,
                Confidence.VERIFIED,
                providerEvidence
            );
        }

        List<Stm32MpBootChainPlan.BootStage> stages = List.of(
            new Stm32MpBootChainPlan.BootStage(
                "stage_rom",
                Stm32MpBootChainPlan.StageKind.ROM,
                "ca35_0",
                "BootROM A35",
                "Masked internal ROM code on Cortex-A35 authenticating TF-A BL2",
                secure,
                Optional.of(new AddressRange("rom", 0x00000000L, 0x20000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_fsbl",
                Stm32MpBootChainPlan.StageKind.FSBL,
                "ca35_0",
                "TF-A BL2",
                "TF-A BL2 FSBL executing in SYSRAM, configuring DDR memory",
                secure,
                Optional.of(new AddressRange("ram", 0x0E000000L, 0x20000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_bl31",
                Stm32MpBootChainPlan.StageKind.SECURE_MONITOR,
                "ca35_0",
                "TF-A BL31",
                "EL3 Runtime Secure Monitor managing PSCI power states and world switches",
                secure,
                Optional.of(new AddressRange("ram", 0x0E020000L, 0x10000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_bl32",
                Stm32MpBootChainPlan.StageKind.SECURE_OS,
                "ca35_0",
                "OP-TEE",
                "Trusted Execution Environment (OP-TEE BL32) in secure RAM",
                secure,
                Optional.of(new AddressRange("ram", 0x0E030000L, 0x10000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_bl33",
                Stm32MpBootChainPlan.StageKind.SSBL,
                "ca35_0",
                "U-Boot",
                "Second Stage Bootloader (U-Boot BL33) in external DDR",
                nonSecure,
                Optional.of(new AddressRange("ram", 0x80000000L, 0x100000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_os",
                Stm32MpBootChainPlan.StageKind.NON_SECURE_OS,
                "ca35_0",
                "Linux Kernel",
                "64-bit Linux Kernel running on Cortex-A35",
                nonSecure,
                Optional.of(new AddressRange("ram", 0x82000000L, 0x2000000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_coprocessor_m33",
                Stm32MpBootChainPlan.StageKind.COPROCESSOR_FIRMWARE,
                "cm33",
                "Cortex-M33 Firmware",
                "Cortex-M33 real-time firmware loaded via remoteproc",
                nonSecure,
                Optional.of(new AddressRange("ram", 0x0E040000L, 0x40000L)),
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        return new Stm32MpBootChainPlan(
            exactPart(),
            Stm32MpBootChainPlan.BootArchitecture.A35_TRUSTED_DOMAIN,
            stages,
            Confidence.VERIFIED,
            providerEvidence
        );
    }

    @Override
    public Stm32MpDeviceTreePlan deviceTreePlan() {
        Stm32MpDeviceTreePlan.RemoteProcNode m33Node = new Stm32MpDeviceTreePlan.RemoteProcNode(
            "m33_rproc",
            "cm33",
            List.of("m33_sram", "vdev0vring0", "vdev0vring1", "vdev0buffer"),
            List.of(
                new Stm32MpDeviceTreePlan.MailboxChannel("vq0", "ipcc1", 0),
                new Stm32MpDeviceTreePlan.MailboxChannel("vq1", "ipcc1", 1)
            ),
            Optional.of("hsem"),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpDeviceTreePlan.MailboxBinding ipcc1 = new Stm32MpDeviceTreePlan.MailboxBinding(
            "ipcc1",
            new AddressRange("periph", 0x46230000L, 0x400L),
            2,
            List.of("ch0", "ch1"),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpDeviceTreePlan.SemaphoreBinding hsem = new Stm32MpDeviceTreePlan.SemaphoreBinding(
            "hsem",
            new AddressRange("periph", 0x46220000L, 0x400L),
            32,
            Confidence.VERIFIED,
            providerEvidence
        );

        List<Stm32MpDeviceTreePlan.ReservedMemoryNode> reserved = List.of(
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("m33_sram",
                new AddressRange("ram", 0x0E040000L, 0x40000L), true, "coprocessor-firmware",
                Confidence.VERIFIED, providerEvidence),
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("vdev0vring0",
                new AddressRange("ram", 0x0E080000L, 0x1000L), true, "rpmsg-vring0",
                Confidence.VERIFIED, providerEvidence),
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("vdev0vring1",
                new AddressRange("ram", 0x0E081000L, 0x1000L), true, "rpmsg-vring1",
                Confidence.VERIFIED, providerEvidence),
            new Stm32MpDeviceTreePlan.ReservedMemoryNode("vdev0buffer",
                new AddressRange("ram", 0x0E082000L, 0x2000L), true, "rpmsg-buffers",
                Confidence.VERIFIED, providerEvidence)
        );

        return new Stm32MpDeviceTreePlan(
            exactPart(),
            "arch/arm64/boot/dts/st/stm32mp257.dtsi",
            "(GPL-2.0-or-later OR BSD-3-Clause)",
            List.of(m33Node),
            List.of(ipcc1),
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
                "rif_controller",
                "RIF",
                new AddressRange("periph", 0x42080000L, 0x1000L),
                secure,
                true,
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<Stm32MpSecurityPlan.OtpSecurityRegion> otp = List.of(
            new Stm32MpSecurityPlan.OtpSecurityRegion(
                "bsec3_otp",
                "BSEC3",
                new AddressRange("periph", 0x44000000L, 0x1000L),
                true,
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        return new Stm32MpSecurityPlan(
            exactPart(),
            Stm32MpSecurityPlan.SecurityArchitecture.RIF_TRUSTZONE,
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
        SecurityDomain smartRun = new SecurityDomain("smart-run", SecurityDomainKind.CUSTOM);

        Stm32MpWorkspacePlan.ProgramSlot linux = new Stm32MpWorkspacePlan.ProgramSlot(
            "ca35-linux-program",
            "ca35_0",
            "64-bit Linux Non-Secure OS",
            FirmwareSource.SHARED_IMAGE,
            "AArch64",
            "AARCH64:LE:64:v8A",
            "default",
            nonSecure,
            Optional.of(new AddressRange("ram", 0x82000000L, 0x2000000L)),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpWorkspacePlan.ProgramSlot secureSlot = new Stm32MpWorkspacePlan.ProgramSlot(
            "ca35-secure-program",
            "ca35_0",
            "TF-A BL31 and OP-TEE Secure OS",
            FirmwareSource.SHARED_IMAGE,
            "AArch64",
            "AARCH64:LE:64:v8A",
            "default",
            secure,
            Optional.of(new AddressRange("ram", 0x0E000000L, 0x40000L)),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpWorkspacePlan.ProgramSlot m33 = new Stm32MpWorkspacePlan.ProgramSlot(
            "cm33-firmware-program",
            "cm33",
            "Cortex-M33 Real-Time Firmware",
            FirmwareSource.INDEPENDENT_IMAGE,
            "ARMv8-M",
            "ARM:LE:32:Cortex",
            "default",
            nonSecure,
            Optional.of(new AddressRange("ram", 0x0E040000L, 0x40000L)),
            Confidence.VERIFIED,
            providerEvidence
        );

        Stm32MpWorkspacePlan.ProgramSlot m0p = new Stm32MpWorkspacePlan.ProgramSlot(
            "cm0p-firmware-program",
            "cm0p",
            "Cortex-M0+ Low-Power SmartRun Firmware",
            FirmwareSource.INDEPENDENT_IMAGE,
            "ARMv6-M",
            "ARM:LE:32:v6M",
            "default",
            smartRun,
            Optional.of(new AddressRange("ram", 0x0E0C0000L, 0x8000L)),
            Confidence.VERIFIED,
            providerEvidence
        );

        List<Stm32MpWorkspacePlan.CrossProgramReference> refs = List.of(
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "boot_handoff_tfa_to_linux",
                Stm32MpWorkspacePlan.ReferenceKind.BOOT_HANDOFF,
                "ca35-secure-program",
                "ca35-linux-program",
                Optional.empty(),
                "TF-A BL31 transfers control to U-Boot and Linux Kernel",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "boot_handoff_linux_to_m33",
                Stm32MpWorkspacePlan.ReferenceKind.BOOT_HANDOFF,
                "ca35-linux-program",
                "cm33-firmware-program",
                Optional.empty(),
                "Linux remoteproc releases Cortex-M33 coprocessor from reset",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "shared_ipcc1_mailbox",
                Stm32MpWorkspacePlan.ReferenceKind.SHARED_MAILBOX,
                "ca35-linux-program",
                "cm33-firmware-program",
                Optional.of(new AddressRange("periph", 0x46230000L, 0x400L)),
                "IPCC1 hardware mailbox registers for A35 <-> M33 RPMsg signaling",
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpWorkspacePlan.CrossProgramReference(
                "shared_hsem_semaphore",
                Stm32MpWorkspacePlan.ReferenceKind.SHARED_SEMAPHORE,
                "ca35-linux-program",
                "cm33-firmware-program",
                Optional.of(new AddressRange("periph", 0x46220000L, 0x400L)),
                "HSEM hardware semaphore for resource isolation synchronization",
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        return new Stm32MpWorkspacePlan(
            exactPart(),
            List.of(linux, secureSlot, m33, m0p),
            refs,
            Confidence.VERIFIED,
            providerEvidence
        );
    }
}
