package io.github.rezabakhshi.embedra.analyzers.plugins;

/**
 * Execution outcome status for a scanner plugin execution (AN-009).
 */
public enum PluginExecutionStatus {
    SUCCESS,
    TIMEOUT,
    LIMIT_EXCEEDED,
    CANCELLED,
    EXECUTION_ERROR,
    RESOURCE_EXHAUSTED
}
