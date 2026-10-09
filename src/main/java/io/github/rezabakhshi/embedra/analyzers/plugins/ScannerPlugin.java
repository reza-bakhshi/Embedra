package io.github.rezabakhshi.embedra.analyzers.plugins;

import java.util.List;

/**
 * Public SPI and execution contract for Embedra local scanner plugins (AN-009).
 */
public interface ScannerPlugin {

    /**
     * Returns the validated manifest metadata for this plugin.
     */
    ScannerPluginManifest manifest();

    /**
     * Executes the plugin against the target scan context under bounded resource limits.
     *
     * @param context scan context containing memory data, strings, budget, and cancellation token
     * @return discovered findings (capped at context.budget().maxFindings())
     * @throws Exception if an unhandled error occurs during scanning
     */
    List<ScannerPluginFinding> scan(PluginScanContext context) throws Exception;
}
