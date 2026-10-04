package io.github.rezabakhshi.embedra.ghidra.function;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra analyzer that automatically normalizes unknown calling conventions and variable
 * storage on functions to standard target ABI conventions.
 */
public final class EmbedraFunctionNormalizerAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Embedra Function ABI & Signature Normalizer";

    public static final String DESCRIPTION = "Normalizes unknown calling conventions and variable "
            + "storage on functions to standard target ABI conventions";

    public EmbedraFunctionNormalizerAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null && program.getFunctionManager() != null;
    }

    @Override
    public boolean added(
            Program program,
            AddressSetView set,
            TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        EmbedraFunctionNormalizerReport report = EmbedraFunctionNormalizer.normalize(program, set, monitor);
        if (log != null && report.callingConventionsNormalized() > 0) {
            log.appendMsg(NAME, "Normalized " + report.callingConventionsNormalized()
                    + " function calling conventions to target ABI default (examined "
                    + report.totalExamined() + " functions)");
        }
        return true;
    }
}
