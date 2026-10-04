package io.github.rezabakhshi.embedra.ghidra.function;

/**
 * Summary report of function ABI and signature normalization.
 *
 * @param totalExamined total number of functions examined
 * @param callingConventionsNormalized number of functions whose calling convention was normalized
 * @param customStorageReset number of functions whose unassigned custom storage was reset
 * @param noReturnMarked number of functions marked as non-returning
 */
public record EmbedraFunctionNormalizerReport(
        int totalExamined,
        int callingConventionsNormalized,
        int customStorageReset,
        int noReturnMarked
) {
    /**
     * Creates an empty report with all counts at zero.
     *
     * @return empty report
     */
    public static EmbedraFunctionNormalizerReport empty() {
        return new EmbedraFunctionNormalizerReport(0, 0, 0, 0);
    }
}
