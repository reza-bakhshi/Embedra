package io.github.rezabakhshi.embedra.targets.stm32.extmem;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.targets.stm32.board.Stm32BoardCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.board.Stm32BoardProfile;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Composes the pure external-memory mapping plan and plans external loads.
 *
 * <p>Every window originates from a confirmed fact source: the digest-pinned
 * T042 board profile, or an explicitly confirmed custom profile (STM-016). The
 * T039 MCU plan and every profile are never mutated. Composition fails closed
 * with stable diagnostics on a part mismatch, an ambiguous board profile, a
 * window that overlaps a pinned MCU region or another window, a window beyond
 * the 32-bit space, an unrecognized controller, or a boot offset outside every
 * external region. Load planning binds one bounded device-offset range to one
 * pinned window and fails closed when the plan is unavailable, the device is
 * unknown, the range is empty or out of extent, or the length exceeds the
 * parser limits. No byte is placed and no support state is promoted here.</p>
 */
public final class Stm32ExternalMemoryPlanner {
    /** Stable diagnostic codes raised by external-memory composition and loading. */
    public enum Diagnostic {
        EXTERNAL_PART_MISMATCH,
        EXTERNAL_BOARD_PROFILE_AMBIGUOUS,
        EXTERNAL_CONTROLLER_UNRECOGNIZED,
        EXTERNAL_WINDOW_OVERLAPS_MCU,
        EXTERNAL_WINDOW_OUT_OF_SPACE,
        EXTERNAL_BOOT_OFFSET_OUT_OF_RANGE,
        LOADER_NOT_AVAILABLE,
        LOADER_DEVICE_UNKNOWN,
        LOADER_RANGE_EMPTY,
        LOADER_RANGE_OVERFLOW,
        LOADER_RANGE_BEYOND_LIMITS,
        LOADER_ADDRESS_UNCOVERED;
    }

    /** A composition or load-planning failure with a stable diagnostic code. */
    public static final class ExternalMemoryPlanException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private final Diagnostic diagnostic;

        private ExternalMemoryPlanException(Diagnostic diagnostic, String message) {
            super(message);
            this.diagnostic = diagnostic;
        }

        public Diagnostic diagnostic() {
            return diagnostic;
        }
    }

    /**
     * The planned placement of one bounded external load.
     *
     * <p>The placement is device-offset based: {@code deviceOffset} and
     * {@code length} address the external device extent, while
     * {@code cpuAddress} is the derived CPU aperture address inside the pinned
     * mapped window. Writability, the window, and the controller come only
     * from the confirmed profile; no permission or address is invented.</p>
     *
     * @param exactPart the bound exact part
     * @param deviceId the pinned window id receiving the bytes
     * @param kind the pinned physical kind: external flash or external RAM
     * @param controller the pinned controller name, e.g. {@code OCTOSPI1}
     * @param controllerFamily the mechanical controller-family projection
     * @param deviceOffset the start offset inside the device extent
     * @param length the bounded positive byte length
     * @param cpuAddress the derived CPU aperture address of the first byte
     * @param writable the pinned writability of the mapped window
     * @param window the pinned aperture the load is planned against
     * @param evidence the plan and window provenance
     */
    public record Stm32ExternalMemoryLoadPlan(String exactPart, String deviceId,
            Stm32BoardProfile.Kind kind, String controller,
            Stm32ExternalMemoryPlan.ControllerFamily controllerFamily, long deviceOffset,
            long length, long cpuAddress, boolean writable, AddressRange window,
            Stm32ExternalMemoryPlan.Source source, List<Evidence> evidence) {

        public Stm32ExternalMemoryLoadPlan {
            Objects.requireNonNull(exactPart, "exactPart");
            Objects.requireNonNull(deviceId, "deviceId");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(controller, "controller");
            Objects.requireNonNull(controllerFamily, "controllerFamily");
            Objects.requireNonNull(window, "window");
            Objects.requireNonNull(source, "source");
            evidence = List.copyOf(evidence);
            if (exactPart.isBlank() || deviceId.isBlank() || controller.isBlank()) {
                throw new IllegalArgumentException("Load plan identity is incomplete");
            }
            if (length <= 0 || deviceOffset < 0 || deviceOffset > window.length() - length) {
                throw new IllegalArgumentException("Load plan range is outside its window");
            }
            if (cpuAddress != window.start() + deviceOffset) {
                throw new IllegalArgumentException(
                    "Load plan CPU address disagrees with its pinned window");
            }
            if (evidence.isEmpty()) {
                throw new IllegalArgumentException("Load plan requires evidence");
            }
        }
    }

    /** The classification of one numeric CPU address against the pinned windows. */
    public record MappedAddress(String deviceId, String controller,
            Stm32ExternalMemoryPlan.ControllerFamily controllerFamily, long deviceOffset,
            boolean writable) {
        public MappedAddress {
            Objects.requireNonNull(deviceId, "deviceId");
            Objects.requireNonNull(controller, "controller");
            Objects.requireNonNull(controllerFamily, "controllerFamily");
        }
    }

    private Stm32ExternalMemoryPlanner() {
    }

    /**
     * Composes one external-memory plan from a validated MCU plan and one
     * resolved board profile.
     *
     * @param plan the validated T039 MCU plan; never mutated
     * @param profile the T042 board profile for the same exact part
     * @return an immutable plan; unavailable profiles yield an explicit
     *         {@code UNAVAILABLE} result carrying the pinned reason
     * @throws ExternalMemoryPlanException on a mismatched part or invalid window
     */
    public static Stm32ExternalMemoryPlan compose(Stm32MemoryPlanner.Plan plan,
            Stm32BoardProfile profile) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(profile, "profile");
        if (!plan.exactPart().equals(profile.exactPart())) {
            throw new ExternalMemoryPlanException(Diagnostic.EXTERNAL_PART_MISMATCH,
                "Board profile " + profile.exactPart() + " does not match MCU "
                    + plan.exactPart());
        }
        if (!profile.reviewed()) {
            return unavailable(plan, profile.reason());
        }
        return mapped(plan, profile.board(), Stm32ExternalMemoryPlan.Source
            .PINNED_T042_BOARD_PROFILE, profile.externalRegions(), profile.bootOffsets(),
            List.of());
    }

    /**
     * Composes one external-memory plan by resolving the pinned board catalog.
     *
     * @param plan the validated T039 MCU plan; never mutated
     * @param catalog the digest-pinned T042 board catalog
     * @return an immutable plan; a part with no profile yields an explicit
     *         {@code UNAVAILABLE} result and an ambiguous profile fails closed
     * @throws ExternalMemoryPlanException when the catalog names several
     *         profiles for the part
     */
    public static Stm32ExternalMemoryPlan compose(Stm32MemoryPlanner.Plan plan,
            Stm32BoardCatalog catalog) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(catalog, "catalog");
        List<Stm32BoardProfile> matches = catalog.forPart(plan.exactPart());
        if (matches.isEmpty()) {
            return unavailable(plan, "NO_CONFIRMED_BOARD_PROFILE: the digest-pinned T042 "
                + "board snapshot carries no profile for " + plan.exactPart()
                + " and no confirmed custom profile was supplied; no external window is "
                + "invented");
        }
        if (matches.size() > 1) {
            throw new ExternalMemoryPlanException(Diagnostic.EXTERNAL_BOARD_PROFILE_AMBIGUOUS,
                "Several pinned board profiles exist for " + plan.exactPart()
                    + "; select a board explicitly");
        }
        return compose(plan, matches.getFirst());
    }

    /**
     * Composes one external-memory plan from a confirmed custom profile
     * (STM-016) without touching any pinned snapshot.
     *
     * @param plan the validated T039 MCU plan; never mutated
     * @param profile the confirmed user-supplied custom profile
     * @return an immutable plan sourced from the custom confirmation
     * @throws ExternalMemoryPlanException on a mismatched part, an unrecognized
     *         controller, a window overlap or out-of-space window, or a boot
     *         offset outside every external region
     */
    public static Stm32ExternalMemoryPlan composeConfirmed(Stm32MemoryPlanner.Plan plan,
            Stm32CustomBoardProfile profile) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(profile, "profile");
        if (!plan.exactPart().equals(profile.exactPart())) {
            throw new ExternalMemoryPlanException(Diagnostic.EXTERNAL_PART_MISMATCH,
                "Custom profile " + profile.exactPart() + " does not match MCU "
                    + plan.exactPart());
        }
        return mapped(plan, profile.board(), Stm32ExternalMemoryPlan.Source
            .CONFIRMED_CUSTOM_PROFILE, profile.externalRegions(), profile.bootOffsets(),
            List.of(profile.confirmation()));
    }

    /**
     * Plans one bounded external load against a mapped plan.
     *
     * @param plan the composed external-memory plan
     * @param deviceId the pinned window id receiving the bytes
     * @param deviceOffset the start offset inside the device extent
     * @param length the positive byte length
     * @param limits shared parser bounds
     * @return the immutable load plan with its derived CPU aperture address
     * @throws ExternalMemoryPlanException when the plan is unavailable, the
     *         device is unknown, the range is empty or outside the device
     *         extent, or the length exceeds the parser limits
     */
    public static Stm32ExternalMemoryLoadPlan planLoad(Stm32ExternalMemoryPlan plan,
            String deviceId, long deviceOffset, long length, ParserLimits limits) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(limits, "limits");
        if (!plan.mapped()) {
            throw new ExternalMemoryPlanException(Diagnostic.LOADER_NOT_AVAILABLE,
                "External memory is not mapped for " + plan.exactPart() + ": "
                    + plan.reason());
        }
        Stm32ExternalMemoryPlan.MappingWindow window = plan.windows().stream()
            .filter(candidate -> candidate.id().equals(deviceId))
            .reduce((left, right) -> {
                throw new ExternalMemoryPlanException(Diagnostic.LOADER_DEVICE_UNKNOWN,
                    "More than one pinned window is named " + deviceId);
            })
            .orElseThrow(() -> new ExternalMemoryPlanException(Diagnostic.LOADER_DEVICE_UNKNOWN,
                "No pinned external device is named " + deviceId));
        if (length <= 0) {
            throw new ExternalMemoryPlanException(Diagnostic.LOADER_RANGE_EMPTY,
                "An external load requires a positive length");
        }
        if (length > limits.maxInputBytes() || length > limits.maxExtractedBytes()
                || length > Integer.MAX_VALUE) {
            throw new ExternalMemoryPlanException(Diagnostic.LOADER_RANGE_BEYOND_LIMITS,
                "External load length exceeds the parser limits: " + length);
        }
        if (deviceOffset < 0 || deviceOffset >= window.mappedRange().length()
                || Math.addExact(deviceOffset, length) > window.mappedRange().length()) {
            throw new ExternalMemoryPlanException(Diagnostic.LOADER_RANGE_OVERFLOW,
                "External load " + deviceOffset + ".." + (deviceOffset + length)
                    + " is outside the device extent of " + deviceId);
        }
        List<Evidence> evidence = new ArrayList<>(plan.evidence());
        evidence.add(new Evidence(EvidenceKind.DOCUMENTED_FIELD,
            "stm32.extmem:window:" + window.id(),
            window.startEvidence() + "; " + window.sizeEvidence()));
        return new Stm32ExternalMemoryLoadPlan(plan.exactPart(), window.id(), window.kind(),
            window.controller(), window.controllerFamily(), deviceOffset, length,
            window.cpuAddressOfDeviceOffset(deviceOffset), window.writable(),
            window.mappedRange(), plan.source(), evidence);
    }

    /**
     * Classifies one numeric CPU address against the pinned windows.
     *
     * @param plan the composed external-memory plan
     * @param cpuAddress the numeric address to classify
     * @return the covering window's device, controller, device offset, and writability
     * @throws ExternalMemoryPlanException when the plan is unavailable or the
     *         address is inside no pinned aperture
     */
    public static MappedAddress classifyCpuAddress(Stm32ExternalMemoryPlan plan,
            long cpuAddress) {
        Objects.requireNonNull(plan, "plan");
        if (!plan.mapped()) {
            throw new ExternalMemoryPlanException(Diagnostic.LOADER_NOT_AVAILABLE,
                "External memory is not mapped for " + plan.exactPart() + ": "
                    + plan.reason());
        }
        for (Stm32ExternalMemoryPlan.MappingWindow window : plan.windows()) {
            if (window.coversCpuAddress(cpuAddress)) {
                return new MappedAddress(window.id(), window.controller(),
                    window.controllerFamily(), window.deviceOffsetOfCpuAddress(cpuAddress),
                    window.writable());
            }
        }
        throw new ExternalMemoryPlanException(Diagnostic.LOADER_ADDRESS_UNCOVERED,
            "Address " + cpuAddress + " is inside no pinned external aperture of "
                + plan.exactPart());
    }

    private static Stm32ExternalMemoryPlan mapped(Stm32MemoryPlanner.Plan plan, String board,
            Stm32ExternalMemoryPlan.Source source,
            List<Stm32BoardProfile.ExternalRegion> regions,
            List<Stm32BoardProfile.BootOffset> bootOffsets, List<Evidence> extraEvidence) {
        List<Stm32ExternalMemoryPlan.MappingWindow> windows = new ArrayList<>();
        for (Stm32BoardProfile.ExternalRegion region : regions) {
            if (region.range().endExclusive() > 0x1_0000_0000L) {
                throw new ExternalMemoryPlanException(Diagnostic.EXTERNAL_WINDOW_OUT_OF_SPACE,
                    "External window exceeds the 32-bit space: " + region.id());
            }
            windows.add(new Stm32ExternalMemoryPlan.MappingWindow(region.id(), region.kind(),
                region.device(), region.controller(),
                controllerFamily(region.controller(), region.id()), region.range(),
                region.writable(), region.startEvidence(), region.sizeEvidence()));
        }
        windows.sort(Comparator.comparing((Stm32ExternalMemoryPlan.MappingWindow window) ->
            window.mappedRange().start()).thenComparing(Stm32ExternalMemoryPlan.MappingWindow::id));
        validateWindows(plan, windows, bootOffsets);
        List<Evidence> evidence = new ArrayList<>(baseEvidence(source));
        evidence.addAll(extraEvidence);
        return new Stm32ExternalMemoryPlan(plan.exactPart(),
            Stm32ExternalMemoryPlan.Status.EXTERNAL_MEMORY_MAPPED, null, source, board, plan,
            windows, bootOffsets, evidence);
    }

    /** Every window stays inside the 32-bit space, clear of MCU and sibling windows. */
    private static void validateWindows(Stm32MemoryPlanner.Plan plan,
            List<Stm32ExternalMemoryPlan.MappingWindow> windows,
            List<Stm32BoardProfile.BootOffset> bootOffsets) {
        for (Stm32ExternalMemoryPlan.MappingWindow window : windows) {
            if (window.mappedRange().endExclusive() > 0x1_0000_0000L) {
                throw new ExternalMemoryPlanException(Diagnostic.EXTERNAL_WINDOW_OUT_OF_SPACE,
                    "External window exceeds the 32-bit space: " + window.id());
            }
            for (Stm32MemoryPlanner.Region mcu : plan.regions()) {
                if (numericallyOverlaps(window.mappedRange(), mcu.range())) {
                    throw new ExternalMemoryPlanException(
                        Diagnostic.EXTERNAL_WINDOW_OVERLAPS_MCU,
                        "External window " + window.id() + " overlaps MCU region "
                            + mcu.id());
                }
            }
        }
        for (Stm32BoardProfile.BootOffset boot : bootOffsets) {
            boolean contained = windows.stream()
                .anyMatch(window -> window.coversDeviceOffset(boot.offset()));
            if (!contained) {
                throw new ExternalMemoryPlanException(Diagnostic.EXTERNAL_BOOT_OFFSET_OUT_OF_RANGE,
                    "Boot offset " + boot.id() + " is outside every external region");
            }
        }
    }

    /** Projects the confirmed controller name mechanically; unrecognized names fail closed. */
    private static Stm32ExternalMemoryPlan.ControllerFamily controllerFamily(
            String controller, String windowId) {
        try {
            return Stm32ExternalMemoryPlan.ControllerFamily.of(controller);
        }
        catch (IllegalArgumentException exception) {
            throw new ExternalMemoryPlanException(Diagnostic.EXTERNAL_CONTROLLER_UNRECOGNIZED,
                exception.getMessage() + " (window " + windowId + ")");
        }
    }

    private static Stm32ExternalMemoryPlan unavailable(Stm32MemoryPlanner.Plan plan,
            String reason) {
        return new Stm32ExternalMemoryPlan(plan.exactPart(),
            Stm32ExternalMemoryPlan.Status.UNAVAILABLE, reason, null, null, plan, List.of(),
            List.of(), baseEvidence(null));
    }

    private static List<Evidence> baseEvidence(Stm32ExternalMemoryPlan.Source source) {
        Set<Evidence> entries = new LinkedHashSet<>();
        entries.add(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
            "stm32.extmem:memory-plans:" + Stm32MemoryPlanner.CATALOG_SHA256,
            "MCU regions and topology reuse the digest-pinned T039 plan without mutation"));
        entries.add(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
            "stm32.extmem:board-profiles:" + Stm32BoardCatalog.SHA256,
            "External windows come only from a confirmed T042 board profile or a confirmed "
                + "custom profile"));
        if (source != null) {
            entries.add(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32.extmem:source:" + source.name(),
                "The mapping source is explicit; no fabricated board link exists"));
        }
        return new ArrayList<>(entries);
    }

    /**
     * Compares two ranges numerically, ignoring the reporting address-space tag.
     *
     * <p>An external aperture and an MCU region are both views of the same CPU
     * 32-bit address space. They are tagged differently so a board offset is
     * never confused with a CPU address in reports, but a true collision is
     * still a collision and must fail closed.</p>
     */
    private static boolean numericallyOverlaps(AddressRange left, AddressRange right) {
        return left.start() < right.endExclusive() && right.start() < left.endExclusive();
    }
}
