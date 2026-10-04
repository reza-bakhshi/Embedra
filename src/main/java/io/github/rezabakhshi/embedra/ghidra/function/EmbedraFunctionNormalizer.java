package io.github.rezabakhshi.embedra.ghidra.function;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.util.Objects;
import java.util.Set;

/**
 * Normalizes unknown calling conventions, variable storage, and signature properties
 * on Ghidra functions to standard target ABI conventions.
 */
public final class EmbedraFunctionNormalizer {

    private static final Set<String> NON_RETURNING_NAMES = Set.of(
            "abort",
            "_abort",
            "panic",
            "_panic",
            "exit",
            "_exit",
            "esp_restart",
            "panichandler",
            "panic_abort",
            "vassertcalled",
            "__assert_func"
    );

    private EmbedraFunctionNormalizer() {
    }

    /**
     * Normalizes all functions or functions within the specified set in the program.
     *
     * @param program program to normalize
     * @param set address set restricting the functions, or null for all functions
     * @param monitor task monitor for cancellation and progress
     * @return normalization summary report
     * @throws CancelledException if cancelled by the user
     */
    public static EmbedraFunctionNormalizerReport normalize(
            Program program,
            AddressSetView set,
            TaskMonitor monitor) throws CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;
        taskMonitor.checkCancelled();

        PrototypeModel defaultModel = program.getCompilerSpec().getDefaultCallingConvention();
        String defaultConvention = defaultModel != null
                ? defaultModel.getName()
                : Function.DEFAULT_CALLING_CONVENTION_STRING;

        int examined = 0;
        int ccNormalized = 0;
        int storageReset = 0;
        int noReturnSet = 0;

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(
                program, "Embedra Function ABI Normalization")) {
            FunctionIterator iter = set != null && !set.isEmpty()
                    ? program.getFunctionManager().getFunctions(set, true)
                    : program.getFunctionManager().getFunctions(true);

            while (iter.hasNext()) {
                taskMonitor.checkCancelled();
                Function func = iter.next();
                examined++;

                // 1. Calling convention normalization
                if (func.hasUnknownCallingConventionName()
                        || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(func.getCallingConventionName())) {
                    try {
                        func.setCallingConvention(defaultConvention);
                        ccNormalized++;
                    } catch (InvalidInputException e) {
                        try {
                            func.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
                            ccNormalized++;
                        } catch (InvalidInputException ignored) {
                            // Target compiler spec does not accept default calling convention string
                        }
                    }
                }

                // 2. Variable storage check: if function has custom variable storage with unassigned return, reset it
                if (func.hasCustomVariableStorage()) {
                    if (func.getReturn() != null && func.getReturn().getVariableStorage().isUnassignedStorage()) {
                        func.setCustomVariableStorage(false);
                        storageReset++;
                    }
                }

                // 3. Common non-returning function detection
                String name = func.getName();
                if (name != null && !func.hasNoReturn()) {
                    String cleanName = name.toLowerCase();
                    if (NON_RETURNING_NAMES.contains(cleanName)
                            || cleanName.contains("panic")
                            || cleanName.contains("abort")) {
                        func.setNoReturn(true);
                        noReturnSet++;
                    }
                }
            }

            tx.commit();
        }

        return new EmbedraFunctionNormalizerReport(examined, ccNormalized, storageReset, noReturnSet);
    }
}
