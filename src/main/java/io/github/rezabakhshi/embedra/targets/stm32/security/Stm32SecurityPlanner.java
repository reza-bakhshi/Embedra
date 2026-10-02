package io.github.rezabakhshi.embedra.targets.stm32.security;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Composes a validated T039 memory plan with one pinned TrustZone record.
 *
 * <p>The MCU plan is never mutated: composition returns a new view whose secure
 * alias regions reuse only the plan's reviewed alias extents. An unavailable
 * part, a part mismatch, an unresolved T039 configuration, an overlap with a
 * memory region, a window whose alias pair disagrees with the plan, an unknown
 * configuration input, or a veneer outside its non-secure-callable boundary
 * fails closed with a stable diagnostic. A partition input is user-supplied
 * configuration, never an invented boundary.</p>
 */
public final class Stm32SecurityPlanner {
    /** Stable diagnostic codes raised by security-map composition. */
    public enum Diagnostic {
        SECURITY_NOT_AVAILABLE,
        SECURITY_PART_MISMATCH,
        SECURITY_PLAN_CONFIGURATION_UNRESOLVED,
        SECURITY_WINDOW_OVERLAP,
        SECURITY_WINDOW_OUT_OF_SPACE,
        SECURITY_WINDOW_UNPAIRED,
        SECURITY_WINDOW_RANGE_MISMATCH,
        SECURITY_CONFIGURATION_UNKNOWN,
        SECURITY_CONFIGURATION_NOT_APPLICABLE,
        SECURITY_CONFIGURATION_OUT_OF_RANGE,
        SECURITY_VENEER_OUTSIDE_NSC,
        SECURITY_VENEER_TARGET_UNKNOWN;
    }

    /** A composition failure with a stable diagnostic code. */
    public static final class SecurityPlanException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private final Diagnostic diagnostic;

        private SecurityPlanException(Diagnostic diagnostic, String message) {
            super(message);
            this.diagnostic = diagnostic;
        }

        public Diagnostic diagnostic() {
            return diagnostic;
        }
    }

    /**
     * One composed security region.
     *
     * @param secureBytes the explicitly supplied secure partition size, or
     *        {@code -1} while the partition stays configuration-dependent
     */
    public record SecurityRegion(String windowId, Stm32SecurityWindow.Kind kind,
            Stm32SecurityAttribute attribute, AddressRange range, String pairedRegionId,
            List<String> pairedAliasIds, Stm32SecurityWindow.PartitionState partitionState,
            long secureBytes) {
        public SecurityRegion {
            Objects.requireNonNull(windowId, "windowId");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(attribute, "attribute");
            Objects.requireNonNull(range, "range");
            Objects.requireNonNull(pairedRegionId, "pairedRegionId");
            pairedAliasIds = List.copyOf(pairedAliasIds);
            Objects.requireNonNull(partitionState, "partitionState");
            if (range.length() <= 0) {
                throw new IllegalArgumentException("Security region requires a positive range");
            }
        }
    }

    /**
     * The immutable result of pairing an MCU plan with a security record.
     *
     * @param mcuPlan the unchanged validated MCU plan
     * @param record the pinned security record
     * @param regions the composed security regions
     * @param veneerTransitions the reviewed evidence-backed transitions
     */
    public record SecurityMap(String exactPart, Stm32MemoryPlanner.Plan mcuPlan,
            Stm32SecurityRecord record, List<SecurityRegion> regions,
            List<Stm32VeneerTransition> veneerTransitions) {
        public SecurityMap {
            Objects.requireNonNull(exactPart, "exactPart");
            Objects.requireNonNull(mcuPlan, "mcuPlan");
            Objects.requireNonNull(record, "record");
            regions = List.copyOf(regions);
            veneerTransitions = List.copyOf(veneerTransitions);
        }

        /** Every exact STM32 part remains PLANNED; composition never promotes. */
        public String supportState() {
            return "PLANNED";
        }

        /** True when every secure alias aperture has an explicit partition input. */
        public boolean partitionResolved() {
            return regions.stream()
                .filter(region -> region.attribute() == Stm32SecurityAttribute.SECURE
                    && region.partitionState()
                        == Stm32SecurityWindow.PartitionState.UNRESOLVED_CONFIGURATION_DEPENDENT)
                .findAny()
                .isEmpty();
        }
    }

    private Stm32SecurityPlanner() {
    }

    /** Composes with no partition input; every partition stays unresolved. */
    public static SecurityMap compose(Stm32MemoryPlanner.Plan plan,
            Stm32SecurityRecord record) {
        return compose(plan, record, Map.of());
    }

    /**
     * Composes a validated MCU plan with one pinned record.
     *
     * @param securePartitions optional user-supplied secure partition sizes in
     *        bytes keyed by secure alias window id; unknown keys fail closed
     */
    public static SecurityMap compose(Stm32MemoryPlanner.Plan plan,
            Stm32SecurityRecord record, Map<String, Long> securePartitions) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(record, "record");
        Objects.requireNonNull(securePartitions, "securePartitions");
        if (!record.pinned()) {
            throw new SecurityPlanException(Diagnostic.SECURITY_NOT_AVAILABLE,
                "Security domains are unavailable for " + record.exactPart() + ": "
                    + record.reason());
        }
        if (!plan.exactPart().equals(record.exactPart())) {
            throw new SecurityPlanException(Diagnostic.SECURITY_PART_MISMATCH,
                "Security record " + record.exactPart() + " does not match MCU "
                    + plan.exactPart());
        }
        if (!plan.unresolvedConfigurationRegions().isEmpty()) {
            throw new SecurityPlanException(Diagnostic.SECURITY_PLAN_CONFIGURATION_UNRESOLVED,
                "MCU plan has unresolved configuration regions for " + plan.exactPart());
        }
        Map<String, Stm32MemoryPlanner.Alias> aliases = new LinkedHashMap<>();
        for (Stm32MemoryPlanner.Alias alias : plan.aliases()) {
            aliases.put(alias.id(), alias);
        }
        Map<String, Stm32MemoryPlanner.Region> regionsById = new LinkedHashMap<>();
        for (Stm32MemoryPlanner.Region region : plan.regions()) {
            regionsById.put(region.id(), region);
        }
        for (Stm32SecurityWindow window : record.windows()) {
            if (window.endExclusive() > 0x1_0000_0000L) {
                throw new SecurityPlanException(Diagnostic.SECURITY_WINDOW_OUT_OF_SPACE,
                    "Security window exceeds the 32-bit space: " + window.id());
            }
            for (Stm32MemoryPlanner.Region region : plan.regions()) {
                if (numericallyOverlaps(window.range(), region.range())) {
                    throw new SecurityPlanException(Diagnostic.SECURITY_WINDOW_OVERLAP,
                        "Security window " + window.id() + " overlaps MCU region "
                            + region.id());
                }
            }
            pair(window, aliases, regionsById);
        }
        for (Stm32SecurityWindow window : record.windows()) {
            if (window.attribute() != Stm32SecurityAttribute.NON_SECURE_CALLABLE) {
                continue;
            }
            boolean insideSecure = record.windows().stream()
                .anyMatch(candidate -> candidate.attribute() == Stm32SecurityAttribute.SECURE
                    && candidate.boundaryKind()
                        == Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE
                    && candidate.covers(window.range()));
            if (!insideSecure) {
                throw new SecurityPlanException(Diagnostic.SECURITY_VENEER_OUTSIDE_NSC,
                    "Non-secure-callable boundary is not inside a secure aperture: "
                        + window.id());
            }
        }
        Map<String, Long> configured = new LinkedHashMap<>();
        for (Map.Entry<String, Long> entry : securePartitions.entrySet()) {
            String windowId = entry.getKey();
            Stm32SecurityWindow window = record.windows().stream()
                .filter(candidate -> candidate.id().equals(windowId))
                .findFirst()
                .orElseThrow(() -> new SecurityPlanException(
                    Diagnostic.SECURITY_CONFIGURATION_UNKNOWN,
                    "Unknown security configuration window: " + windowId));
            if (window.attribute() != Stm32SecurityAttribute.SECURE
                    || window.boundaryKind()
                        != Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE) {
                throw new SecurityPlanException(Diagnostic.SECURITY_CONFIGURATION_NOT_APPLICABLE,
                    "Security configuration does not apply to window: " + windowId);
            }
            Long size = entry.getValue();
            if (size == null || size <= 0 || size > window.size()) {
                throw new SecurityPlanException(Diagnostic.SECURITY_CONFIGURATION_OUT_OF_RANGE,
                    "Security configuration is outside window " + windowId);
            }
            configured.put(windowId, size);
        }
        for (Stm32VeneerTransition transition : record.veneerEvidence().transitions()) {
            boolean covered = record.windows().stream()
                .anyMatch(window -> window.attribute()
                        == Stm32SecurityAttribute.NON_SECURE_CALLABLE
                    && window.covers(transition.nscRange()));
            if (!covered) {
                throw new SecurityPlanException(Diagnostic.SECURITY_VENEER_OUTSIDE_NSC,
                    "Veneer transition is not inside a pinned NSC boundary: "
                        + transition.id());
            }
            if (!regionsById.containsKey(transition.secureTargetRegionId())) {
                throw new SecurityPlanException(Diagnostic.SECURITY_VENEER_TARGET_UNKNOWN,
                    "Veneer transition targets an unknown secure region: "
                        + transition.id());
            }
        }
        List<SecurityRegion> composed = new ArrayList<>();
        for (Stm32SecurityWindow window : record.windows()) {
            Long configuredSize = configured.get(window.id());
            composed.add(new SecurityRegion(window.id(), window.kind(), window.attribute(),
                window.range(), window.pairedRegionId(), window.pairedAliasIds(),
                configuredSize == null ? window.partitionState()
                    : Stm32SecurityWindow.PartitionState.CONFIGURATION_INPUT,
                configuredSize == null ? -1L : configuredSize));
        }
        return new SecurityMap(plan.exactPart(), plan, record, composed,
            record.veneerEvidence().transitions());
    }

    private static void pair(Stm32SecurityWindow window,
            Map<String, Stm32MemoryPlanner.Alias> aliases,
            Map<String, Stm32MemoryPlanner.Region> regions) {
        if (window.boundaryKind() == Stm32SecurityWindow.BoundaryKind.PARTITION) {
            if (!regions.containsKey(window.pairedRegionId())) {
                throw new SecurityPlanException(Diagnostic.SECURITY_WINDOW_UNPAIRED,
                    "Security boundary has no paired MCU region: " + window.id());
            }
            return;
        }
        for (String aliasId : window.pairedAliasIds()) {
            Stm32MemoryPlanner.Alias alias = aliases.get(aliasId);
            if (alias == null || !alias.target().equals(window.pairedRegionId())) {
                throw new SecurityPlanException(Diagnostic.SECURITY_WINDOW_UNPAIRED,
                    "Security window alias is missing from the MCU plan: " + aliasId);
            }
            if (alias.range().start() != window.start()
                    || alias.range().length() != window.size()) {
                throw new SecurityPlanException(Diagnostic.SECURITY_WINDOW_RANGE_MISMATCH,
                    "Security window and MCU alias extent disagree: " + aliasId);
            }
        }
    }

    private static boolean numericallyOverlaps(AddressRange left, AddressRange right) {
        return left.start() < right.endExclusive() && right.start() < left.endExclusive();
    }
}
