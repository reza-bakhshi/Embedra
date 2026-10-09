package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Thread-safe registry and discovery manager for local scanner plugins (AN-009).
 */
public final class ScannerPluginRegistry {

    private final Map<String, ScannerPlugin> plugins = new ConcurrentHashMap<>();

    public ScannerPluginRegistry() {
    }

    /**
     * Registers a pre-instantiated scanner plugin.
     *
     * @param plugin plugin instance to register
     * @throws DiagnosticException if a plugin with the same ID is already registered
     */
    public void register(ScannerPlugin plugin) throws DiagnosticException {
        Objects.requireNonNull(plugin, "plugin must not be null");
        String id = plugin.manifest().pluginId();
        if (plugins.putIfAbsent(id, plugin) != null) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID,
                    "Duplicate scanner plugin registration for ID: " + id, null));
        }
    }

    /**
     * Parses and registers a declarative plugin from a JSON manifest string.
     */
    public ScannerPlugin registerDeclarativePlugin(
            String jsonManifest,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        ScannerPluginManifest manifest = ScannerPluginManifest.parse(jsonManifest, limits, token);
        if (manifest.pluginType() != PluginType.DECLARATIVE_RULE) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID,
                    "registerDeclarativePlugin requires pluginType DECLARATIVE_RULE", null));
        }
        DeclarativeScannerPlugin plugin = new DeclarativeScannerPlugin(manifest);
        register(plugin);
        return plugin;
    }

    /**
     * Loads and registers a plugin from a JSON manifest file.
     */
    public ScannerPlugin registerManifest(
            Path manifestPath,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException, IOException {
        Objects.requireNonNull(manifestPath, "manifestPath must not be null");
        token.throwIfCancellationRequested();

        if (!Files.isRegularFile(manifestPath)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.PLUGIN_MANIFEST_INVALID,
                    "Plugin manifest file not found: " + manifestPath, null));
        }

        byte[] bytes = Files.readAllBytes(manifestPath);
        ScannerPluginManifest manifest = ScannerPluginManifest.parse(bytes, limits, token);

        if (manifest.pluginType() == PluginType.DECLARATIVE_RULE) {
            DeclarativeScannerPlugin plugin = new DeclarativeScannerPlugin(manifest);
            register(plugin);
            return plugin;
        } else {
            // For JAVA_CLASS, instantiate via reflection if entryPoint is set
            try {
                Class<?> clazz = Class.forName(manifest.entryPoint());
                if (!ScannerPlugin.class.isAssignableFrom(clazz)) {
                    throw new DiagnosticException(Diagnostic.error(
                            DiagnosticCode.PLUGIN_MANIFEST_INVALID,
                            "Entry point does not implement ScannerPlugin: " + manifest.entryPoint(), null));
                }
                ScannerPlugin plugin = (ScannerPlugin) clazz.getDeclaredConstructor().newInstance();
                register(plugin);
                return plugin;
            } catch (Exception e) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.PLUGIN_EXECUTION_FAILED,
                        "Failed to instantiate plugin class: " + e.getMessage(), null));
            }
        }
    }

    /**
     * Discovers and registers all JSON plugin manifests within a directory.
     */
    public int discoverPluginsInDirectory(
            Path directory,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException, IOException {
        Objects.requireNonNull(directory, "directory must not be null");
        if (!Files.isDirectory(directory)) {
            return 0;
        }

        int count = 0;
        try (Stream<Path> stream = Files.walk(directory, limits.maxNestingDepth())) {
            List<Path> files = stream
                    .filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".json"))
                    .toList();

            for (Path p : files) {
                token.throwIfCancellationRequested();
                try {
                    registerManifest(p, limits, token);
                    count++;
                } catch (Exception e) {
                    // Skip or log invalid files in discovery mode
                }
            }
        }
        return count;
    }

    /**
     * Unregisters a plugin by ID.
     */
    public boolean unregister(String pluginId) {
        return plugins.remove(pluginId) != null;
    }

    /**
     * Retrieves a registered plugin by ID.
     */
    public ScannerPlugin get(String pluginId) {
        return plugins.get(pluginId);
    }

    /**
     * Returns an unmodifiable collection of all registered plugins.
     */
    public Collection<ScannerPlugin> allPlugins() {
        return Collections.unmodifiableCollection(plugins.values());
    }

    /**
     * Executes all registered plugins matching the target platform under bounded limits.
     */
    public ScannerPluginBatchReport executeAll(PluginScanContext context) {
        try (ScannerPluginRunner runner = new ScannerPluginRunner()) {
            return executeAll(context, runner);
        }
    }

    /**
     * Executes all registered plugins matching the target platform using an existing runner.
     */
    public ScannerPluginBatchReport executeAll(PluginScanContext context, ScannerPluginRunner runner) {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(runner, "runner must not be null");

        long start = System.nanoTime();
        List<ScannerPluginExecutionResult> results = new ArrayList<>();

        for (ScannerPlugin plugin : plugins.values()) {
            if (context.cancellationToken().isCancellationRequested()) {
                break;
            }

            ScannerPluginManifest manifest = plugin.manifest();
            // Filter by platform
            if (!"ALL".equalsIgnoreCase(manifest.targetPlatform())
                    && !manifest.targetPlatform().equalsIgnoreCase(context.platform())) {
                continue;
            }

            ScannerPluginExecutionResult res = runner.execute(plugin, context);
            results.add(res);
        }

        Duration total = Duration.ofNanos(System.nanoTime() - start);
        return ScannerPluginBatchReport.of(results, total);
    }

    /**
     * Clears all registered plugins.
     */
    public void clear() {
        plugins.clear();
    }
}
