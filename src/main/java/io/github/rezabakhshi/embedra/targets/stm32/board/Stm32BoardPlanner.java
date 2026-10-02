package io.github.rezabakhshi.embedra.targets.stm32.board;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Composes a validated MCU memory plan with a reviewed board profile.
 *
 * <p>The MCU plan is never mutated: this planner returns a new view that pairs
 * the unchanged MCU regions with additive external board regions. An unavailable
 * profile, a part mismatch, an external region that collides with an MCU region
 * or with another external region, or a boot offset outside its stated external
 * region fails closed with a stable diagnostic. The planner never invents an
 * address, size, permission, or board-to-part link.</p>
 */
public final class Stm32BoardPlanner {
    /** External addresses live in their own space, so they never alias a CPU range. */
    public static final String EXTERNAL_ADDRESS_SPACE = "ext-mem";

    private Stm32BoardPlanner() {
    }

    /** Stable diagnostic codes raised by board-plan composition. */
    public enum Diagnostic {
        BOARD_NOT_AVAILABLE,
        BOARD_PART_MISMATCH,
        EXTERNAL_REGION_OVERLAP,
        EXTERNAL_REGION_OUT_OF_SPACE,
        BOOT_OFFSET_OUT_OF_RANGE;
    }

    /** A composition failure with a stable diagnostic code. */
    public static final class BoardPlanException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private final Diagnostic diagnostic;

        private BoardPlanException(Diagnostic diagnostic, String message) {
            super(message);
            this.diagnostic = diagnostic;
        }

        public Diagnostic diagnostic() {
            return diagnostic;
        }
    }

    /**
     * The result of pairing an MCU plan with a board profile.
     *
     * @param mcuPlan the unchanged validated MCU plan
     * @param profile the reviewed board profile
     * @param externalRegions the additive external regions, unmodified
     * @param bootOffsets the reviewed boot offsets, unmodified
     */
    public record BoardPlan(Stm32MemoryPlanner.Plan mcuPlan, Stm32BoardProfile profile,
            List<Stm32BoardProfile.ExternalRegion> externalRegions,
            List<Stm32BoardProfile.BootOffset> bootOffsets) {
        public BoardPlan {
            Objects.requireNonNull(mcuPlan, "mcuPlan");
            Objects.requireNonNull(profile, "profile");
            externalRegions = List.copyOf(externalRegions);
            bootOffsets = List.copyOf(bootOffsets);
        }

        public String exactPart() {
            return mcuPlan.exactPart();
        }

        public long externalRamBytes() {
            return externalRegions.stream()
                .filter(region -> region.kind()
                    == Stm32BoardProfile.Kind.EXTERNAL_RAM_MEMORY_MAPPED)
                .mapToLong(region -> region.range().length()).sum();
        }

        public long externalFlashBytes() {
            return externalRegions.stream()
                .filter(region -> region.kind()
                    == Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED)
                .mapToLong(region -> region.range().length()).sum();
        }
    }

    /**
     * Pairs one validated MCU plan with one reviewed board profile.
     *
     * @param mcuPlan a validated exact-part MCU memory plan
     * @param profile a reviewed board profile for the same exact part
     * @return an immutable board plan; the MCU plan is never modified
     * @throws BoardPlanException when the profile is unavailable, mismatched,
     *         overlapping, or out of space
     */
    public static BoardPlan compose(Stm32MemoryPlanner.Plan mcuPlan,
            Stm32BoardProfile profile) {
        Objects.requireNonNull(mcuPlan, "mcuPlan");
        Objects.requireNonNull(profile, "profile");
        if (!profile.reviewed()) {
            throw new BoardPlanException(Diagnostic.BOARD_NOT_AVAILABLE,
                "Board profile is unavailable: " + profile.reason());
        }
        if (!mcuPlan.exactPart().equals(profile.exactPart())) {
            throw new BoardPlanException(Diagnostic.BOARD_PART_MISMATCH,
                "Board profile " + profile.exactPart() + " does not match MCU "
                    + mcuPlan.exactPart());
        }
        for (Stm32BoardProfile.ExternalRegion region : profile.externalRegions()) {
            if (region.range().endExclusive() > 0x1_0000_0000L) {
                throw new BoardPlanException(Diagnostic.EXTERNAL_REGION_OUT_OF_SPACE,
                    "External region exceeds the 32-bit space: " + region.id());
            }
            for (Stm32MemoryPlanner.Region mcu : mcuPlan.regions()) {
                if (numericallyOverlaps(region.range(), mcu.range())) {
                    throw new BoardPlanException(Diagnostic.EXTERNAL_REGION_OVERLAP,
                        "External region " + region.id() + " overlaps MCU region "
                            + mcu.id());
                }
            }
        }
        for (int left = 0; left < profile.externalRegions().size(); left++) {
            for (int right = left + 1; right < profile.externalRegions().size(); right++) {
                if (numericallyOverlaps(profile.externalRegions().get(left).range(),
                        profile.externalRegions().get(right).range())) {
                    throw new BoardPlanException(Diagnostic.EXTERNAL_REGION_OVERLAP,
                        "External regions overlap: "
                            + profile.externalRegions().get(left).id() + " and "
                            + profile.externalRegions().get(right).id());
                }
            }
        }
        for (Stm32BoardProfile.BootOffset boot : profile.bootOffsets()) {
            boolean contained = profile.externalRegions().stream()
                .anyMatch(region -> boot.offset() >= region.range().start()
                    && boot.offset() < region.range().endExclusive());
            if (!contained) {
                throw new BoardPlanException(Diagnostic.BOOT_OFFSET_OUT_OF_RANGE,
                    "Boot offset " + boot.id() + " is outside every external region");
            }
        }
        return new BoardPlan(mcuPlan, profile, profile.externalRegions(),
            profile.bootOffsets());
    }

    /**
     * Compares two ranges numerically, ignoring the reporting address-space tag.
     *
     * <p>An external-memory mapped region and an MCU region are both views of the
     * same CPU 32-bit address space. They are tagged differently so a board offset
     * is never confused with a CPU address in reports, but a true collision is
     * still a collision and must fail closed.</p>
     */
    private static boolean numericallyOverlaps(AddressRange left, AddressRange right) {
        return left.start() < right.endExclusive() && right.start() < left.endExclusive();
    }

    /** All external regions for a part, flattened for report consumers. */
    public static List<Stm32BoardProfile.ExternalRegion> externalRegions(BoardPlan plan) {
        Objects.requireNonNull(plan, "plan");
        return new ArrayList<>(plan.externalRegions());
    }
}
