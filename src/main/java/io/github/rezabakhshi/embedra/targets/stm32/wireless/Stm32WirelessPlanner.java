package io.github.rezabakhshi.embedra.targets.stm32.wireless;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32DevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32SvdApplicability;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlan;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlan.ImageDomain.State;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Composes one exact-part wireless/network-core record and evaluates the
 * separately supplied coprocessor-firmware binding.
 *
 * <p>Every input is a digest-pinned artifact record; the T039 plan and the
 * T045 workspace are never mutated. Composition fails closed with stable
 * diagnostics on a part mismatch, a family outside the WB/WB0/WBA/WL3 scope,
 * an inconsistent workspace status, and an unresolvable or ambiguous per-core
 * SVD-tag mapping. The binding evaluator classifies a caller-supplied
 * candidate image range against pinned CPU2 memory attribution only; it never
 * places bytes, never claims a resolved fetch view, and never invents CPU2
 * access.</p>
 */
public final class Stm32WirelessPlanner {
    /** Stable diagnostic codes raised by wireless composition and binding. */
    public enum Diagnostic {
        WIRELESS_PART_MISMATCH,
        WIRELESS_FAMILY_OUT_OF_SCOPE,
        WIRELESS_WORKSPACE_UNPINNED,
        WIRELESS_WORKSPACE_INAPPLICABLE,
        WIRELESS_CORE_ROLE_MAPPING_UNRESOLVED,
        WIRELESS_CORE_ROLE_MAPPING_AMBIGUOUS,
        BINDING_PART_MISMATCH,
        BINDING_WORKSPACE_UNPINNED,
        BINDING_IMAGE_EMPTY,
        BINDING_IMAGE_OUT_OF_SPACE,
        BINDING_RANGE_NOT_CPU2_ACCESSIBLE;
    }

    /** A composition or binding failure with a stable diagnostic code. */
    public static final class WirelessPlanException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private final Diagnostic diagnostic;

        private WirelessPlanException(Diagnostic diagnostic, String message) {
            super(message);
            this.diagnostic = diagnostic;
        }

        public Diagnostic diagnostic() {
            return diagnostic;
        }
    }

    /**
     * The binding classification of one caller-supplied CPU2 image range.
     *
     * <p>Every state stays configuration-dependent: the pinned C2OPT/SBRV
     * fetch view is unresolved for a bindable range, and a device flash range
     * is marked CPU1-image-and-configuration-dependent, never pinned access.
     * {@code regionIds} names the pinned plan regions that fully cover the
     * candidate; no placement, content, or size is produced.</p>
     */
    public record NetworkCoreImageBinding(String exactPart, State state, List<String> regionIds,
            Stm32WorkspacePlan.UnresolvedView fetchView) {
        /** The classification of a separately supplied coprocessor image. */
        public enum State {
            BINDABLE_UNRESOLVED_FETCH_VIEW, FLASH_VIEW_CONFIGURATION_DEPENDENT
        }

        public NetworkCoreImageBinding {
            Objects.requireNonNull(exactPart, "exactPart");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(regionIds, "regionIds");
            Objects.requireNonNull(fetchView, "fetchView");
            regionIds = List.copyOf(regionIds);
            if (exactPart.isBlank()) {
                throw new IllegalArgumentException("Binding requires an exact part");
            }
            if (regionIds.isEmpty()) {
                throw new IllegalArgumentException("A binding classification requires regions");
            }
        }
    }

    private Stm32WirelessPlanner() {
    }

    /**
     * Composes one wireless record.
     *
     * @param workspace the T045 workspace plan; required and pinned for the
     *        WB55/WB15 network-core parts, optional and unpinned elsewhere
     */
    public static Stm32WirelessRecord compose(Stm32DevicePackRegistry.Part catalogPart,
            Stm32MemoryPlanner.Plan plan, Stm32WorkspacePlan workspace,
            Stm32SecurityRecord securityRecord, Stm32SvdApplicability.Entry entry) {
        Objects.requireNonNull(catalogPart, "catalogPart");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(securityRecord, "securityRecord");
        Objects.requireNonNull(entry, "entry");
        String exactPart = plan.exactPart();
        if (!catalogPart.exactPart().equals(exactPart)
                || !securityRecord.exactPart().equals(exactPart)
                || !entry.exactPart().equals(exactPart)) {
            throw new WirelessPlanException(Diagnostic.WIRELESS_PART_MISMATCH,
                "Wireless inputs cover different exact parts: catalog "
                    + catalogPart.exactPart() + ", plan " + exactPart + ", security "
                    + securityRecord.exactPart() + ", applicability " + entry.exactPart());
        }
        if (workspace != null && !workspace.exactPart().equals(exactPart)) {
            throw new WirelessPlanException(Diagnostic.WIRELESS_PART_MISMATCH,
                "Workspace " + workspace.exactPart() + " does not match MCU " + exactPart);
        }
        Stm32WirelessRecord.Series series = series(catalogPart.family());
        List<ProcessorNode> cores = plan.topology().processors().stream()
            .filter(node -> node.kind() == ProcessorKind.CPU_CORE)
            .toList();
        boolean dualCoreTopology = cores.size() > 1;
        if (dualCoreTopology && (workspace == null || !workspace.pinned())) {
            throw new WirelessPlanException(Diagnostic.WIRELESS_WORKSPACE_UNPINNED,
                "A two-core topology requires the pinned workspace plan for " + exactPart);
        }
        if (!dualCoreTopology && workspace != null && workspace.pinned()) {
            throw new WirelessPlanException(Diagnostic.WIRELESS_WORKSPACE_INAPPLICABLE,
                "A single-core topology cannot carry a pinned workspace plan: " + exactPart);
        }
        ProcessorNode application = cores.stream()
            .filter(node -> node.firmwareSource() == FirmwareSource.SHARED_IMAGE)
            .findFirst()
            .orElse(null);
        if (application == null) {
            throw new WirelessPlanException(Diagnostic.WIRELESS_PART_MISMATCH,
                "No pinned shared-image application core in the plan for " + exactPart);
        }
        Stm32WirelessRecord.CoreRole applicationCore = coreRole(application, entry, true);
        Stm32WirelessRecord.RadioSubsystem radio = radioSubsystem(dualCoreTopology, entry);
        Stm32WirelessRecord.NetworkCore networkCore = null;
        Stm32WirelessRecord.SharedResources sharedResources;
        Stm32WirelessRecord.Status status;
        if (dualCoreTopology) {
            Stm32WorkspacePlan.ProgramSlot slot = networkSlot(workspace);
            ProcessorNode node = cores.stream()
                .filter(candidate -> candidate.id().equals(slot.nodeId()))
                .findFirst()
                .orElseThrow(() -> new WirelessPlanException(Diagnostic.WIRELESS_PART_MISMATCH,
                    "Workspace network slot names an unknown CPU core: " + slot.nodeId()));
            Stm32WirelessRecord.CoreRole core = coreRole(node, entry, false);
            Stm32WirelessRecord.CoprocessorFirmware firmware =
                firmware(slot, workspace);
            networkCore = new Stm32WirelessRecord.NetworkCore(core, firmware,
                communicationRanges(workspace));
            status = Stm32WirelessRecord.Status.NETWORK_CORE_PINNED;
            sharedResources = new Stm32WirelessRecord.SharedResources(
                Stm32WirelessRecord.SharedResources.State
                    .SHARED_RESOURCES_IN_PINNED_WORKSPACE_PLAN, workspace);
        }
        else {
            status = Stm32WirelessRecord.Status.SINGLE_APPLICATION_CORE;
            sharedResources = new Stm32WirelessRecord.SharedResources(
                Stm32WirelessRecord.SharedResources.State
                    .UNAVAILABLE_NO_PINNED_RADIO_MEMORY_ATTRIBUTION, null);
        }
        return new Stm32WirelessRecord(exactPart, series, status,
            applicationCore, radio, sharedResources, networkCore, securityRecord, evidence());
    }

    /**
     * Classifies one candidate coprocessor-image range against the pinned
     * CPU2 memory attribution of a pinned workspace part.
     *
     * @param image the candidate address-bearing image range; bytes are never read
     */
    public static NetworkCoreImageBinding evaluateNetworkCoreImage(
            Stm32MemoryPlanner.Plan plan, Stm32WorkspacePlan workspace, AddressRange image) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(workspace, "workspace");
        if (!plan.exactPart().equals(workspace.exactPart())) {
            throw new WirelessPlanException(Diagnostic.BINDING_PART_MISMATCH,
                "Workspace " + workspace.exactPart() + " does not match MCU " + plan.exactPart());
        }
        if (!workspace.pinned()) {
            throw new WirelessPlanException(Diagnostic.BINDING_WORKSPACE_UNPINNED,
                "Coprocessor binding requires the pinned workspace plan");
        }
        if (image == null || image.length() <= 0) {
            throw new WirelessPlanException(Diagnostic.BINDING_IMAGE_EMPTY,
                "A coprocessor image range must be positive");
        }
        if (!"ram".equals(image.addressSpace()) || image.endExclusive() > 0x1_0000_0000L) {
            throw new WirelessPlanException(Diagnostic.BINDING_IMAGE_OUT_OF_SPACE,
                "A coprocessor image range must fit the pinned 32-bit MCU space");
        }
        List<String> cpu2Regions = new ArrayList<>();
        long cpu2Coverage = 0L;
        for (Stm32MemoryPlanner.Region region : plan.regions()) {
            if (!"RAM".equals(region.kind()) || !region.sharedAccess().containsKey("cpu2")) {
                continue;
            }
            java.util.Optional<AddressRange> intersection =
                region.range().intersection(image);
            if (intersection.isPresent()) {
                cpu2Coverage += intersection.get().length();
                cpu2Regions.add(region.id());
            }
        }
        Stm32WorkspacePlan.UnresolvedView fetchView = networkSlot(workspace).unresolvedViews()
            .getFirst();
        if (cpu2Coverage == image.length()) {
            return new NetworkCoreImageBinding(plan.exactPart(),
                NetworkCoreImageBinding.State.BINDABLE_UNRESOLVED_FETCH_VIEW, cpu2Regions,
                fetchView);
        }
        for (Stm32MemoryPlanner.Region region : plan.regions()) {
            if (!"FLASH".equals(region.kind())) {
                continue;
            }
            java.util.Optional<AddressRange> intersection =
                region.range().intersection(image);
            if (intersection.isEmpty() || intersection.get().length() != image.length()) {
                continue;
            }
            return new NetworkCoreImageBinding(
                plan.exactPart(),
                NetworkCoreImageBinding.State.FLASH_VIEW_CONFIGURATION_DEPENDENT,
                List.of(region.id()),
                fetchView);
        }
        throw new WirelessPlanException(Diagnostic.BINDING_RANGE_NOT_CPU2_ACCESSIBLE,
            "Coprocessor image range " + image.start() + ".." + image.endExclusive()
                + " is not covered by pinned CPU2 memory or the device flash");
    }

    private static Stm32WorkspacePlan.ProgramSlot networkSlot(Stm32WorkspacePlan workspace) {
        return workspace.programs().stream()
            .filter(slot -> slot.firmwareSource() == FirmwareSource.INDEPENDENT_IMAGE)
            .reduce((left, right) -> {
                throw new WirelessPlanException(
                    Diagnostic.WIRELESS_CORE_ROLE_MAPPING_AMBIGUOUS,
                    "More than one independently supplied program slot is pinned: "
                        + left.id() + ", " + right.id());
            })
            .orElseThrow(() -> new WirelessPlanException(
                Diagnostic.WIRELESS_CORE_ROLE_MAPPING_UNRESOLVED,
                "No independently supplied program slot is pinned: "
                    + workspace.exactPart()));
    }

    private static Stm32WirelessRecord.CoprocessorFirmware firmware(
            Stm32WorkspacePlan.ProgramSlot slot, Stm32WorkspacePlan workspace) {
        if (slot.unresolvedViews().isEmpty()) {
            throw new WirelessPlanException(Diagnostic.WIRELESS_CORE_ROLE_MAPPING_UNRESOLVED,
                "No pinned configuration-dependent fetch view for " + slot.id());
        }
        Stm32WorkspacePlan.UnresolvedView unresolved = slot.unresolvedViews().getFirst();
        String mechanism = workspace.crossProgramReferences().stream()
            .filter(reference -> reference.kind()
                == Stm32WorkspacePlan.CrossProgramReference.Kind.BOOT_HANDOFF
                && reference.toSlotId().equals(slot.id()))
            .findFirst()
            .map(Stm32WorkspacePlan.CrossProgramReference::mechanism)
            .orElseThrow(() -> new WirelessPlanException(
                Diagnostic.WIRELESS_CORE_ROLE_MAPPING_UNRESOLVED,
                "No pinned boot-order mechanism for " + slot.id()));
        return new Stm32WirelessRecord.CoprocessorFirmware(
            Stm32WirelessRecord.CoprocessorFirmware.State.INDEPENDENTLY_SUPPLIED,
            Stm32WirelessRecord.CoprocessorFirmware.Binding.UNRESOLVED_CONFIGURATION_DEPENDENT,
            mechanism, new Stm32WirelessRecord.UnresolvedFetchView(unresolved.id(),
                unresolved.reason()));
    }

    private static List<AddressRange> communicationRanges(Stm32WorkspacePlan workspace) {
        Set<AddressRange> ranges = new LinkedHashSet<>();
        workspace.crossProgramReferences().stream()
            .filter(reference -> reference.kind()
                == Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_MAILBOX
                || reference.kind()
                    == Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_SEMAPHORE)
            .forEach(reference -> ranges.addAll(reference.sharedRanges()));
        return List.copyOf(ranges);
    }

    private static Stm32WirelessRecord.CoreRole coreRole(ProcessorNode node,
            Stm32SvdApplicability.Entry entry, boolean application) {
        Stm32SvdApplicability.SvdFile file = fileFor(entry, node.role(), entry.exactPart());
        Stm32WirelessRecord.RegisterModel model;
        String reason;
        if (file != null && entry.status() == Stm32SvdApplicability.Status.EXACT_SVD_SHIPPED) {
            model = Stm32WirelessRecord.RegisterModel.SHIPPED;
            reason = null;
        }
        else if (file != null && entry.status()
                == Stm32SvdApplicability.Status.EXACT_SVD_DEFERRED) {
            model = Stm32WirelessRecord.RegisterModel.DEFERRED;
            reason = entry.reason() == null
                ? "REGISTER_MODEL_MATERIALIZATION_DEFERRED"
                : entry.reason();
        }
        else if (entry.status() == Stm32SvdApplicability.Status.EXACT_SVD_SHIPPED
                || entry.status() == Stm32SvdApplicability.Status.EXACT_SVD_DEFERRED) {
            if (entry.reason() == null) {
                throw new WirelessPlanException(Diagnostic.WIRELESS_CORE_ROLE_MAPPING_UNRESOLVED,
                    "The resolved applicability entry pins no SVD file for core " + node.role()
                        + " of " + entry.exactPart());
            }
            model = Stm32WirelessRecord.RegisterModel.UNAVAILABLE;
            reason = entry.reason();
        }
        else {
            model = Stm32WirelessRecord.RegisterModel.UNAVAILABLE;
            reason = entry.reason() == null
                ? "NO_MATCHING_REGISTER_MODEL_FOR_CORE"
                : entry.reason();
        }
        return new Stm32WirelessRecord.CoreRole(node.id(), node.role(), node.firmwareSource(),
            node.instructionSet().orElseThrow(), node.ghidraLanguageId().orElseThrow(),
            node.compilerSpecId().orElseThrow(), node.securityDomain(), model, reason, file);
    }

    /** Mechanical projection of the pinned CPU label onto pinned SVD file tags. */
    private static Stm32SvdApplicability.SvdFile fileFor(Stm32SvdApplicability.Entry entry,
            String role, String exactPart) {
        Stm32SvdApplicability.SvdFile matching = null;
        for (Stm32SvdApplicability.SvdFile file : entry.svdFiles()) {
            if (!tagMatches(file.cpu(), role)) {
                continue;
            }
            if (matching != null) {
                throw new WirelessPlanException(Diagnostic.WIRELESS_CORE_ROLE_MAPPING_AMBIGUOUS,
                    "More than one pinned SVD file matches core " + role + " of " + exactPart);
            }
            matching = file;
        }
        return matching;
    }

    private static boolean tagMatches(String cpuTag, String role) {
        String core = role.toUpperCase(Locale.ROOT);
        return switch (cpuTag.toUpperCase(Locale.ROOT)) {
            case "CM4" -> core.contains("CORTEX-M4");
            case "CM0", "CM0+" -> core.contains("CORTEX-M0");
            case "CM33" -> core.contains("CORTEX-M33");
            default -> false;
        };
    }

    private static Stm32WirelessRecord.RadioSubsystem radioSubsystem(boolean dualCore,
            Stm32SvdApplicability.Entry entry) {
        Stm32WirelessRecord.Management management = dualCore
            ? Stm32WirelessRecord.Management.NETWORK_CORE_MANAGED
            : Stm32WirelessRecord.Management.APPLICATION_CORE_MANAGED;
        String reason;
        if (entry.status() == Stm32SvdApplicability.Status.EXACT_SVD_SHIPPED) {
            reason = "RADIO_REGISTERS_NOT_IN_PINNED_REGISTER_MODELS";
        }
        else if (entry.status() == Stm32SvdApplicability.Status.EXACT_SVD_DEFERRED) {
            reason = "RADIO_REGISTERS_DEFERRED_WITH_THE_DEVICE_LINE";
        }
        else {
            reason = "RADIO_REGISTERS_UNAVAILABLE_WITH_THE_DEVICE_LINE";
        }
        return new Stm32WirelessRecord.RadioSubsystem(management,
            Stm32WirelessRecord.RegisterModel.UNAVAILABLE, reason);
    }

    private static Stm32WirelessRecord.Series series(String family) {
        return switch (family) {
            case "STM32WB" -> Stm32WirelessRecord.Series.WB;
            case "STM32WB0" -> Stm32WirelessRecord.Series.WB0;
            case "STM32WBA" -> Stm32WirelessRecord.Series.WBA;
            case "STM32WL3" -> Stm32WirelessRecord.Series.WL3;
            default -> throw new WirelessPlanException(Diagnostic.WIRELESS_FAMILY_OUT_OF_SCOPE,
                "Family " + family + " is outside the pinned WB/WB0/WBA/WL3 wireless scope");
        };
    }

    private static List<Evidence> evidence() {
        return List.of(
            new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32.wireless:curated-catalog:" + Stm32DevicePackRegistry.CATALOG_SHA256,
                "Series identity comes from the digest-pinned curated family label"),
            new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32.wireless:memory-plans:" + Stm32MemoryPlanner.CATALOG_SHA256,
                "Core counts, roles, communication windows, and topology reuse the "
                    + "digest-pinned T039 plan without mutation"),
            new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32.wireless:svd-applicability:" + Stm32SvdApplicability.SHA256,
                "Per-core register-model states reuse the digest-pinned T040 review"),
            new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32.wireless:security-domains:" + Stm32SecurityCatalog.SHA256,
                "TrustZone views come only from the digest-pinned T044 record"));
    }
}
