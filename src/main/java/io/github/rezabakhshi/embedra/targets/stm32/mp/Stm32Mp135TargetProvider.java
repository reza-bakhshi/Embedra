package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.BootRelationship;
import io.github.rezabakhshi.embedra.core.model.BootRelationshipType;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.ResetEntry;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Target provider for the single Cortex-A7 STM32MP135 microprocessor series.
 *
 * <p>Unlike the dual-core MP157 and MP257 parts, the MP135 features a single Cortex-A7
 * core and contains no Cortex-M microcontroller core. Sourced from Apache-2.0
 * ST CMSIS headers (cmsis_device_mp13) and OpenOCD target scripts.</p>
 */
public final class Stm32Mp135TargetProvider implements Stm32MpTargetProvider {
    public static final String PROVIDER_ID =
        "io.github.rezabakhshi.embedra.targets.stm32.mp.stm32mp135";

    public static final String PROVIDER_VERSION = "1.0.0";

    public static final String EXACT_PART = "STM32MP135F";

    public static final String LINE = "STM32MP135";

    public static final String FAMILY = "STM32MP1";

    private static final Set<String> MATCH_KEYS = Set.of(
        "STM32MP135", "STM32MP135A", "STM32MP135C", "STM32MP135D", "STM32MP135F",
        "STM32MP135AAE7", "STM32MP135CAE7", "STM32MP135DAE7", "STM32MP135FAE7", "STM32MP135FAF7"
    );

    private final List<Evidence> providerEvidence = List.of(
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "STMicroelectronics RM0475",
            "STM32MP135 Reference Manual RM0475"),
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "ST CMSIS device headers",
            "cmsis_device_mp13 fbbe3df (Apache-2.0)"),
        new Evidence(EvidenceKind.DOCUMENTED_FIELD, "OpenOCD target script",
            "stm32mp13x.cfg (GPL-2.0-or-later)")
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
        return MATCH_KEYS.contains(normalized) || normalized.startsWith("STM32MP135");
    }

    @Override
    public SupportDecision supports(String exactPartOrLine) {
        if (matches(exactPartOrLine)) {
            return new SupportDecision(true, Optional.of(exactPart()),
                "STM32MP135 single Cortex-A7 application processor",
                providerEvidence);
        }
        return new SupportDecision(false, Optional.empty(),
            "Not matched by STM32MP135 provider",
            List.of());
    }

    @Override
    public ExecutionTopology topology() {
        SecurityDomain nonSecure = SecurityDomain.nonSecure();
        SecurityDomain secure = SecurityDomain.secure();

        ProcessorNode ca7 = new ProcessorNode(
            "ca7",
            ProcessorKind.CPU_CORE,
            Optional.of("ARMv7-A"),
            Optional.of("ARM:LE:32:v7"),
            Optional.of("default"),
            "APPLICATION",
            nonSecure,
            "ca7",
            Set.of("ram", "rom"),
            List.of(new ResetEntry("ca7_reset", "ram", 0xC2000000L, Confidence.DERIVED, providerEvidence)),
            FirmwareSource.SHARED_IMAGE,
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
                new AddressRange("ram", 0x2FFE0000L, 0x20000L),
                Set.of("ca7"),
                Set.of("ca7"),
                Set.of("ca7"),
                List.of(),
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        List<BootRelationship> bootRelations = List.of(
            new BootRelationship(
                "bootrom_releases_ca7",
                "bootrom",
                "ca7",
                BootRelationshipType.RELEASES_FROM_RESET,
                "SoC reset vector execution jumps to FSBL on Cortex-A7",
                Confidence.VERIFIED,
                providerEvidence
            )
        );

        return new ExecutionTopology(
            List.of(ca7, bootrom),
            sharedMemories,
            bootRelations,
            List.of(),
            List.of(),
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
                "ca7",
                "TF-A BL2",
                "First Stage Bootloader (TF-A BL2) executing in SYSRAM",
                secure,
                Optional.of(new AddressRange("ram", 0x2FFE0000L, 0x10000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_secure_os",
                Stm32MpBootChainPlan.StageKind.SECURE_OS,
                "ca7",
                "OP-TEE",
                "Trusted Execution Environment (OP-TEE BL32) in secure RAM",
                secure,
                Optional.of(new AddressRange("ram", 0x2FFF0000L, 0x10000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_ssbl",
                Stm32MpBootChainPlan.StageKind.SSBL,
                "ca7",
                "U-Boot",
                "Second Stage Bootloader (U-Boot BL33) in DDR",
                nonSecure,
                Optional.of(new AddressRange("ram", 0xC0100000L, 0x100000L)),
                Confidence.VERIFIED,
                providerEvidence
            ),
            new Stm32MpBootChainPlan.BootStage(
                "stage_os",
                Stm32MpBootChainPlan.StageKind.NON_SECURE_OS,
                "ca7",
                "Linux Kernel",
                "Linux Operating System on Cortex-A7",
                nonSecure,
                Optional.of(new AddressRange("ram", 0xC2000000L, 0x2000000L)),
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
        return new Stm32MpDeviceTreePlan(
            exactPart(),
            "arch/arm/boot/dts/st/stm32mp135f-dk.dts",
            "(GPL-2.0+ OR BSD-3-Clause)",
            List.of(),
            List.of(),
            List.of(),
            List.of(),
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
            List.of(),
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
            "ca7",
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
            "ca7",
            "TF-A and OP-TEE Secure World",
            FirmwareSource.SHARED_IMAGE,
            "ARMv7-A",
            "ARM:LE:32:v7",
            "default",
            secure,
            Optional.of(new AddressRange("ram", 0x2FFE0000L, 0x20000L)),
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
            )
        );

        return new Stm32MpWorkspacePlan(
            exactPart(),
            List.of(linux, secureSlot),
            refs,
            Confidence.VERIFIED,
            providerEvidence
        );
    }
}
