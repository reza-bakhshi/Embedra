package io.github.rezabakhshi.embedra.analyzers.plugins;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Immutable execution result for a single scanner plugin run (AN-009).
 *
 * @param pluginId identifier of the executed plugin
 * @param status execution outcome status
 * @param findings findings collected during execution (capped at maxFindings)
 * @param duration elapsed wall time
 * @param bytesScanned total bytes inspected
 * @param diagnosticMessage human-readable error or diagnostic message if not successful
 */
public record ScannerPluginExecutionResult(
        String pluginId,
        PluginExecutionStatus status,
        List<ScannerPluginFinding> findings,
        Duration duration,
        long bytesScanned,
        String diagnosticMessage) {

    public ScannerPluginExecutionResult {
        Objects.requireNonNull(pluginId, "pluginId must not be null");
        Objects.requireNonNull(status, "status must not be null");
        findings = findings == null ? List.of() : List.copyOf(findings);
        duration = duration == null ? Duration.ZERO : duration;
        if (bytesScanned < 0) {
            throw new IllegalArgumentException("bytesScanned must be non-negative: " + bytesScanned);
        }
    }

    /**
     * Checks if the execution completed successfully.
     */
    public boolean isSuccessful() {
        return status == PluginExecutionStatus.SUCCESS;
    }
}
