package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Configuration context for PIO state machine instructions, tracking wrap addresses
 * and side-set settings along with explicit uncertainty states.
 */
public record RpPioConfig(
        int sideSetCount,
        boolean sideSetOptional,
        boolean sideSetPinDirs,
        int wrapTarget,
        int wrap,
        boolean isWrapUncertain) {

    public RpPioConfig {
        if (sideSetCount < -1 || sideSetCount > 5) {
            throw new IllegalArgumentException("Side-set count must be between -1 (unknown) and 5: " + sideSetCount);
        }
    }

    public static RpPioConfig unconfigured() {
        return new RpPioConfig(-1, false, false, -1, -1, true);
    }

    public static RpPioConfig withDefaults(int programLength) {
        int w = Math.max(0, Math.min(31, programLength - 1));
        return new RpPioConfig(-1, false, false, 0, w, true);
    }

    public static RpPioConfig of(
            int sideSetCount,
            boolean sideSetOptional,
            boolean sideSetPinDirs,
            int wrapTarget,
            int wrap) {
        return new RpPioConfig(sideSetCount, sideSetOptional, sideSetPinDirs, wrapTarget, wrap, false);
    }

    public boolean isSideSetKnown() {
        return sideSetCount >= 0;
    }

    public boolean isWrapExplicit() {
        return !isWrapUncertain && wrapTarget >= 0 && wrap >= 0;
    }
}
