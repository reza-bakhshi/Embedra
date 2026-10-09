package io.github.rezabakhshi.embedra.analyzers.plugins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingConfidence;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class AdversarialScannerPluginTest {

    private ScannerPluginRunner runner;

    @BeforeEach
    void setUp() {
        runner = new ScannerPluginRunner();
    }

    @AfterEach
    void tearDown() {
        runner.close();
    }

    @Test
    @Timeout(5)
    void infiniteLoopPluginTimesOutWithinBudget() {
        ScannerPlugin hangPlugin = new ScannerPlugin() {
            @Override
            public ScannerPluginManifest manifest() {
                return createTestManifest("adversarial.hang", 100);
            }

            @Override
            public List<ScannerPluginFinding> scan(PluginScanContext context) throws Exception {
                // Hostile infinite loop
                while (!Thread.currentThread().isInterrupted()) {
                    // spin
                }
                return List.of();
            }
        };

        PluginResourceBudget budget = new PluginResourceBudget(100, 1024 * 1024, 10);
        PluginScanContext context = new PluginScanContext(
                new byte[10], 0L, List.of(), Map.of(), "ALL", budget, CancellationToken.none());

        ScannerPluginExecutionResult result = runner.execute(hangPlugin, context);

        assertEquals(PluginExecutionStatus.TIMEOUT, result.status());
        assertFalse(result.isSuccessful());
        assertNotNull(result.diagnosticMessage());
        assertTrue(result.diagnosticMessage().contains(DiagnosticCode.PLUGIN_TIMEOUT.id()));
        assertTrue(result.duration().toMillis() >= 90);
    }

    @Test
    @Timeout(5)
    void reDoSAttackTerminatesSafelyUnderTimeout() {
        // Catastrophic backtracking regex (a+)+$
        DeclarativeRuleDefinition evilRule = new DeclarativeRuleDefinition(
                "redos-rule",
                "Catastrophic backtracking attempt",
                DeclarativeMatcherType.REGEX,
                "(a+)+$",
                FindingSeverity.HIGH,
                FindingConfidence.LEAD,
                0.5,
                false,
                FindingCategory.CUSTOM_PLUGIN,
                "REDOS",
                null,
                null
        );

        ScannerPluginManifest manifest = new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                "adversarial.redos",
                "ReDoS Plugin",
                "1.0.0",
                "Attacker",
                "ReDoS attack",
                PluginType.DECLARATIVE_RULE,
                "ALL",
                null,
                Set.of(PluginCapability.STRING_SCAN),
                new PluginResourceBudget(150, 1024 * 1024, 10),
                List.of(evilRule)
        );

        DeclarativeScannerPlugin plugin = new DeclarativeScannerPlugin(manifest);

        // Evil input triggering exponential backtracking
        String evilInput = "a".repeat(28) + "!";
        PluginScanContext context = new PluginScanContext(
                evilInput.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1),
                0L,
                List.of(),
                Map.of(),
                "ALL",
                new PluginResourceBudget(150, 1024 * 1024, 10),
                CancellationToken.none()
        );

        ScannerPluginExecutionResult result = runner.execute(plugin, context);

        // Must either complete safely or time out without hanging the VM
        assertTrue(result.status() == PluginExecutionStatus.SUCCESS
                || result.status() == PluginExecutionStatus.TIMEOUT);
    }

    @Test
    void memoryBombIsContainedSafely() {
        ScannerPlugin oomPlugin = new ScannerPlugin() {
            @Override
            public ScannerPluginManifest manifest() {
                return createTestManifest("adversarial.oom", 2000);
            }

            @Override
            public List<ScannerPluginFinding> scan(PluginScanContext context) {
                throw new OutOfMemoryError("Hostile memory exhaustion attempt");
            }
        };

        PluginScanContext context = PluginScanContext.ofBytes(new byte[10]);
        ScannerPluginExecutionResult result = runner.execute(oomPlugin, context);

        assertEquals(PluginExecutionStatus.RESOURCE_EXHAUSTED, result.status());
        assertFalse(result.isSuccessful());
        assertTrue(result.diagnosticMessage().contains("OutOfMemoryError"));
    }

    @Test
    void stackOverflowBombIsContainedSafely() {
        ScannerPlugin stackBomb = new ScannerPlugin() {
            @Override
            public ScannerPluginManifest manifest() {
                return createTestManifest("adversarial.stackoverflow", 2000);
            }

            @Override
            public List<ScannerPluginFinding> scan(PluginScanContext context) {
                return recursiveBomb(0);
            }

            private List<ScannerPluginFinding> recursiveBomb(int depth) {
                return recursiveBomb(depth + 1);
            }
        };

        PluginScanContext context = PluginScanContext.ofBytes(new byte[10]);
        ScannerPluginExecutionResult result = runner.execute(stackBomb, context);

        assertEquals(PluginExecutionStatus.EXECUTION_ERROR, result.status());
        assertFalse(result.isSuccessful());
        assertTrue(result.diagnosticMessage().contains("StackOverflowError"));
    }

    @Test
    void findingFloodingIsCappedAtBudget() {
        ScannerPlugin floodPlugin = new ScannerPlugin() {
            @Override
            public ScannerPluginManifest manifest() {
                return createTestManifest("adversarial.flood", 2000);
            }

            @Override
            public List<ScannerPluginFinding> scan(PluginScanContext context) {
                List<ScannerPluginFinding> flood = new ArrayList<>();
                for (int i = 0; i < 5000; i++) {
                    flood.add(new ScannerPluginFinding(
                            "flood-" + i,
                            "adversarial.flood",
                            FindingCategory.CUSTOM_PLUGIN,
                            "FLOOD",
                            FindingSeverity.INFO,
                            FindingConfidence.LEAD,
                            0.1,
                            "ALL",
                            i,
                            1,
                            "X",
                            "Flood item",
                            false,
                            Map.of()
                    ));
                }
                return flood;
            }
        };

        PluginResourceBudget budget = new PluginResourceBudget(2000, 1024 * 1024, 25);
        PluginScanContext context = new PluginScanContext(
                new byte[10], 0L, List.of(), Map.of(), "ALL", budget, CancellationToken.none());

        ScannerPluginExecutionResult result = runner.execute(floodPlugin, context);

        assertEquals(PluginExecutionStatus.LIMIT_EXCEEDED, result.status());
        assertEquals(25, result.findings().size());
        assertTrue(result.diagnosticMessage().contains("exceeded max limit"));
    }

    @Test
    void uncaughtExceptionIsTrappedGracefully() {
        ScannerPlugin thrower = new ScannerPlugin() {
            @Override
            public ScannerPluginManifest manifest() {
                return createTestManifest("adversarial.thrower", 2000);
            }

            @Override
            public List<ScannerPluginFinding> scan(PluginScanContext context) {
                throw new NullPointerException("Null dereference simulation");
            }
        };

        PluginScanContext context = PluginScanContext.ofBytes(new byte[10]);
        ScannerPluginExecutionResult result = runner.execute(thrower, context);

        assertEquals(PluginExecutionStatus.EXECUTION_ERROR, result.status());
        assertFalse(result.isSuccessful());
        assertTrue(result.diagnosticMessage().contains("NullPointerException"));
    }

    @Test
    void cooperativeCancellationAbortsExecution() {
        AtomicBoolean cancelled = new AtomicBoolean(true);
        ScannerPlugin slowPlugin = new ScannerPlugin() {
            @Override
            public ScannerPluginManifest manifest() {
                return createTestManifest("adversarial.slow", 2000);
            }

            @Override
            public List<ScannerPluginFinding> scan(PluginScanContext context) throws Exception {
                context.cancellationToken().throwIfCancellationRequested();
                return List.of();
            }
        };

        PluginScanContext context = new PluginScanContext(
                new byte[10], 0L, List.of(), Map.of(), "ALL",
                PluginResourceBudget.defaults(), cancelled::get);

        ScannerPluginExecutionResult result = runner.execute(slowPlugin, context);

        assertEquals(PluginExecutionStatus.CANCELLED, result.status());
    }

    @Test
    void rejectsPathTraversalInManifests() {
        List<String> badPaths = List.of(
                "../relative/escape.jar",
                "..\\windows\\escape.dll",
                "/absolute/path/scanner.class",
                "\\network\\share\\scanner.class",
                "folder/../../escape",
                "bad\0null"
        );

        for (String bad : badPaths) {
            String jsonVal = bad.replace("\\", "\\\\").replace("\0", "\\u0000");
            String json = """
                    {
                      "schemaId": "urn:embedra:schema:scanner-plugin-manifest:1",
                      "pluginId": "bad.path",
                      "name": "Bad Path",
                      "version": "1.0.0",
                      "author": "Attacker",
                      "description": "Path traversal",
                      "pluginType": "JAVA_CLASS",
                      "entryPoint": "%s",
                      "capabilities": ["BYTE_SCAN"],
                      "resourceLimits": {"maxWallTimeMs": 1000, "maxMemoryBytes": 1048576, "maxFindings": 10}
                    }
                    """.formatted(jsonVal);

            DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                    ScannerPluginManifest.parse(json, ParserLimits.defaults(), CancellationToken.none()));

            assertEquals(DiagnosticCode.PLUGIN_PATH_UNSAFE, ex.diagnostic().code(), "Should reject: " + bad);
        }
    }

    @Test
    void secretRedactionMasksTargetInReports() {
        ScannerPluginFinding secretFinding = new ScannerPluginFinding(
                "FND-SECRET",
                "plugin.secret",
                FindingCategory.SECURITY_LEAD,
                "PASSWORD",
                FindingSeverity.CRITICAL,
                FindingConfidence.CONFIRMED,
                1.0,
                "ESP32",
                0x1000L,
                12,
                "topsecretpass123",
                "Candidate master password",
                true,
                Map.of()
        );

        ScannerPluginExecutionResult execRes = new ScannerPluginExecutionResult(
                "plugin.secret",
                PluginExecutionStatus.SUCCESS,
                List.of(secretFinding),
                Duration.ofMillis(50),
                100,
                null
        );

        ScannerPluginBatchReport report = ScannerPluginBatchReport.of(List.of(execRes), Duration.ofMillis(50));

        // Masked export
        String maskedJson = report.toJson(true);
        assertTrue(maskedJson.contains("[REDACTED_SECRET]"));
        assertFalse(maskedJson.contains("topsecretpass123"));

        String maskedMd = report.toMarkdown(true);
        assertTrue(maskedMd.contains("[REDACTED_SECRET]"));
        assertFalse(maskedMd.contains("topsecretpass123"));

        // Raw export when explicitly requested
        String rawJson = report.toJson(false);
        assertTrue(rawJson.contains("topsecretpass123"));

        String rawMd = report.toMarkdown(false);
        assertTrue(rawMd.contains("topsecretpass123"));
    }

    @Test
    @Timeout(10)
    void concurrentExecutionIsSafeAndIsolated() throws Exception {
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch latch = new CountDownLatch(threads);
        List<ScannerPluginExecutionResult> results = new java.util.concurrent.CopyOnWriteArrayList<>();

        for (int i = 0; i < threads; i++) {
            final int id = i;
            pool.submit(() -> {
                try {
                    ScannerPlugin plugin = new ScannerPlugin() {
                        @Override
                        public ScannerPluginManifest manifest() {
                            return createTestManifest("concurrent." + id, 1000);
                        }

                        @Override
                        public List<ScannerPluginFinding> scan(PluginScanContext context) {
                            return List.of(new ScannerPluginFinding(
                                    "fnd-" + id,
                                    "concurrent." + id,
                                    FindingCategory.CUSTOM_PLUGIN,
                                    "THREAD_MATCH",
                                    FindingSeverity.INFO,
                                    FindingConfidence.LEAD,
                                    0.5,
                                    "ALL",
                                    id * 100L,
                                    4,
                                    "VAL_" + id,
                                    "Concurrent match",
                                    false,
                                    Map.of()
                            ));
                        }
                    };

                    PluginScanContext ctx = PluginScanContext.ofBytes(new byte[] {(byte) id});
                    results.add(runner.execute(plugin, ctx));
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(threads, results.size());
        for (ScannerPluginExecutionResult res : results) {
            assertTrue(res.isSuccessful());
            assertEquals(1, res.findings().size());
        }
    }

    private static ScannerPluginManifest createTestManifest(String id, long maxWallTimeMs) {
        return new ScannerPluginManifest(
                ScannerPluginManifest.SCHEMA_ID,
                id,
                "Test Plugin",
                "1.0.0",
                "Tester",
                "Description",
                PluginType.JAVA_CLASS,
                "ALL",
                "dummy.entry.Point",
                Set.of(PluginCapability.BYTE_SCAN),
                new PluginResourceBudget(maxWallTimeMs, 1024 * 1024, 100),
                List.of()
        );
    }
}
