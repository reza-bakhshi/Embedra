package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Execution context passed to scanner plugins during analysis (AN-009).
 *
 * @param data raw memory buffer or binary data
 * @param baseAddress starting memory address
 * @param strings extracted strings available in the target image
 * @param metadata program options and architecture metadata
 * @param platform target architecture or device platform
 * @param budget resource limits allocated for this execution
 * @param cancellationToken cooperative cancellation token
 */
public record PluginScanContext(
        byte[] data,
        long baseAddress,
        List<ExtractedString> strings,
        Map<String, String> metadata,
        String platform,
        PluginResourceBudget budget,
        CancellationToken cancellationToken) {

    public PluginScanContext {
        data = data == null ? new byte[0] : data;
        if (baseAddress < 0) {
            throw new IllegalArgumentException("baseAddress must be non-negative: " + baseAddress);
        }
        strings = strings == null ? List.of() : List.copyOf(strings);
        metadata = metadata == null ? Map.of() : Collections.unmodifiableMap(Map.copyOf(metadata));
        platform = (platform == null || platform.isBlank()) ? "GENERIC" : platform;
        budget = budget == null ? PluginResourceBudget.defaults() : budget;
        cancellationToken = cancellationToken == null ? CancellationToken.none() : cancellationToken;
    }

    /**
     * Creates a minimal context from raw bytes.
     */
    public static PluginScanContext ofBytes(byte[] data) {
        return new PluginScanContext(
                data,
                0L,
                List.of(),
                Map.of(),
                "GENERIC",
                PluginResourceBudget.defaults(),
                CancellationToken.none()
        );
    }
}
