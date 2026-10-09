package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Bounded execution sandbox enforcing wall-time, memory, and error containment for plugins (AN-009).
 */
public final class ScannerPluginRunner implements AutoCloseable {

    private final ExecutorService executor;

    private final boolean ownsExecutor;

    public ScannerPluginRunner() {
        this(Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "Embedra-ScannerPlugin-Worker");
            t.setDaemon(true);
            return t;
        }), true);
    }

    public ScannerPluginRunner(ExecutorService executor) {
        this(executor, false);
    }

    private ScannerPluginRunner(ExecutorService executor, boolean ownsExecutor) {
        this.executor = Objects.requireNonNull(executor, "executor must not be null");
        this.ownsExecutor = ownsExecutor;
    }

    /**
     * Executes the given plugin within the configured resource bounds of the context.
     *
     * @param plugin scanner plugin to execute
     * @param context scan context containing data, budget, and cancellation token
     * @return execution result capturing status, findings, and diagnostic info
     */
    public ScannerPluginExecutionResult execute(ScannerPlugin plugin, PluginScanContext context) {
        Objects.requireNonNull(plugin, "plugin must not be null");
        Objects.requireNonNull(context, "context must not be null");

        String pluginId = plugin.manifest().pluginId();
        PluginResourceBudget budget = context.budget();

        if (context.cancellationToken().isCancellationRequested()) {
            return new ScannerPluginExecutionResult(
                    pluginId,
                    PluginExecutionStatus.CANCELLED,
                    List.of(),
                    Duration.ZERO,
                    context.data().length,
                    "Execution cancelled before start"
            );
        }

        long startTime = System.nanoTime();
        Future<List<ScannerPluginFinding>> future = executor.submit(() -> plugin.scan(context));

        try {
            List<ScannerPluginFinding> findings = future.get(budget.maxWallTimeMs(), TimeUnit.MILLISECONDS);
            Duration duration = Duration.ofNanos(System.nanoTime() - startTime);

            if (context.cancellationToken().isCancellationRequested()) {
                return new ScannerPluginExecutionResult(
                        pluginId,
                        PluginExecutionStatus.CANCELLED,
                        List.of(),
                        duration,
                        context.data().length,
                        "Execution cancelled during scan"
                );
            }

            if (findings != null && findings.size() > budget.maxFindings()) {
                List<ScannerPluginFinding> capped = findings.subList(0, budget.maxFindings());
                return new ScannerPluginExecutionResult(
                        pluginId,
                        PluginExecutionStatus.LIMIT_EXCEEDED,
                        capped,
                        duration,
                        context.data().length,
                        "Findings count (" + findings.size() + ") exceeded max limit (" + budget.maxFindings() + ")"
                );
            }

            return new ScannerPluginExecutionResult(
                    pluginId,
                    PluginExecutionStatus.SUCCESS,
                    findings == null ? List.of() : findings,
                    duration,
                    context.data().length,
                    null
            );
        } catch (TimeoutException e) {
            future.cancel(true);
            Duration duration = Duration.ofNanos(System.nanoTime() - startTime);
            return new ScannerPluginExecutionResult(
                    pluginId,
                    PluginExecutionStatus.TIMEOUT,
                    List.of(),
                    duration,
                    context.data().length,
                    "Plugin timed out after " + budget.maxWallTimeMs() + " ms ("
                            + DiagnosticCode.PLUGIN_TIMEOUT.id() + ")"
            );
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            Duration duration = Duration.ofNanos(System.nanoTime() - startTime);
            return new ScannerPluginExecutionResult(
                    pluginId,
                    PluginExecutionStatus.CANCELLED,
                    List.of(),
                    duration,
                    context.data().length,
                    "Plugin execution interrupted"
            );
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            Duration duration = Duration.ofNanos(System.nanoTime() - startTime);

            if (cause instanceof OutOfMemoryError) {
                return new ScannerPluginExecutionResult(
                        pluginId,
                        PluginExecutionStatus.RESOURCE_EXHAUSTED,
                        List.of(),
                        duration,
                        context.data().length,
                        "Plugin exhausted memory budget (OutOfMemoryError)"
                );
            }

            if (cause instanceof StackOverflowError) {
                return new ScannerPluginExecutionResult(
                        pluginId,
                        PluginExecutionStatus.EXECUTION_ERROR,
                        List.of(),
                        duration,
                        context.data().length,
                        "Plugin exceeded maximum stack depth (StackOverflowError)"
                );
            }

            if (cause instanceof DiagnosticException de) {
                if (de.diagnostic().code() == DiagnosticCode.CANCELLED) {
                    return new ScannerPluginExecutionResult(
                            pluginId,
                            PluginExecutionStatus.CANCELLED,
                            List.of(),
                            duration,
                            context.data().length,
                            "Plugin cooperatively cancelled"
                    );
                }
                if (de.diagnostic().code() == DiagnosticCode.LIMIT_EXCEEDED
                        || de.diagnostic().code() == DiagnosticCode.PLUGIN_LIMIT_EXCEEDED) {
                    return new ScannerPluginExecutionResult(
                            pluginId,
                            PluginExecutionStatus.LIMIT_EXCEEDED,
                            List.of(),
                            duration,
                            context.data().length,
                            de.getMessage()
                    );
                }
            }

            return new ScannerPluginExecutionResult(
                    pluginId,
                    PluginExecutionStatus.EXECUTION_ERROR,
                    List.of(),
                    duration,
                    context.data().length,
                    "Plugin error: " + cause.getClass().getSimpleName() + " - " + cause.getMessage()
            );
        }
    }

    @Override
    public void close() {
        if (ownsExecutor) {
            executor.shutdownNow();
        }
    }
}
