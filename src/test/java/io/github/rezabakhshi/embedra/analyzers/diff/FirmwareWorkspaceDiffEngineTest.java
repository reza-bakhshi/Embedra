package io.github.rezabakhshi.embedra.analyzers.diff;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FirmwareWorkspaceDiffEngineTest {

    private final FirmwareWorkspaceDiffEngine engine = new FirmwareWorkspaceDiffEngine();

    @Test
    void diffsFunctionsAcrossAllChangeKinds() throws Exception {
        WorkspaceSnapshot src = new WorkspaceSnapshot(
                "v1.0",
                List.of(
                        new FunctionSnapshot("main", 0x1000, 64, "hash1", "void main()"),
                        new FunctionSnapshot("calc", 0x1100, 32, "hash2", "int calc(int)"),
                        new FunctionSnapshot("helper", 0x1200, 16, "hash3", "void helper()"),
                        new FunctionSnapshot("obsolete", 0x1300, 20, "hash4", "void obsolete()")
                ),
                List.of(), List.of(), List.of(), List.of(), List.of()
        );

        WorkspaceSnapshot tgt = new WorkspaceSnapshot(
                "v1.1",
                List.of(
                        new FunctionSnapshot("main", 0x1000, 64, "hash1", "void main()"), // UNCHANGED
                        new FunctionSnapshot("calc", 0x1100, 48, "hash2_mod", "int calc(int)"), // MODIFIED
                        new FunctionSnapshot("helper", 0x1500, 16, "hash3", "void helper()"), // MOVED
                        new FunctionSnapshot("new_feature", 0x1600, 40, "hash5", "void new_feature()") // ADDED
                        // obsolete is REMOVED
                ),
                List.of(), List.of(), List.of(), List.of(), List.of()
        );

        FirmwareWorkspaceDiff diff = engine.compare(src, tgt);

        assertEquals("v1.0", diff.sourceWorkspace());
        assertEquals("v1.1", diff.targetWorkspace());
        assertEquals(5, diff.functions().size());

        FunctionDiffEntry mainEntry = diff.functions().stream()
                .filter(f -> f.functionName().equals("main")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.UNCHANGED, mainEntry.changeKind());

        FunctionDiffEntry calcEntry = diff.functions().stream()
                .filter(f -> f.functionName().equals("calc")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.MODIFIED, calcEntry.changeKind());

        FunctionDiffEntry helperEntry = diff.functions().stream()
                .filter(f -> f.functionName().equals("helper")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.MOVED, helperEntry.changeKind());

        FunctionDiffEntry obsoleteEntry = diff.functions().stream()
                .filter(f -> f.functionName().equals("obsolete")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.REMOVED, obsoleteEntry.changeKind());

        FunctionDiffEntry newEntry = diff.functions().stream()
                .filter(f -> f.functionName().equals("new_feature")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.ADDED, newEntry.changeKind());

        assertEquals(4, diff.functionDifferenceCount());
    }

    @Test
    void diffsSymbolsCorrectly() throws Exception {
        WorkspaceSnapshot src = new WorkspaceSnapshot(
                "v1", List.of(),
                List.of(
                        new SymbolSnapshot("g_counter", 0x2000, "Variable", "global"),
                        new SymbolSnapshot("g_moved", 0x2004, "Variable", "global"),
                        new SymbolSnapshot("g_removed", 0x2008, "Variable", "global"),
                        new SymbolSnapshot("poly", 0x2010, "Variable", "global")
                ),
                List.of(), List.of(), List.of(), List.of()
        );

        WorkspaceSnapshot tgt = new WorkspaceSnapshot(
                "v2", List.of(),
                List.of(
                        new SymbolSnapshot("g_counter", 0x2000, "Variable", "global"), // UNCHANGED
                        new SymbolSnapshot("g_moved", 0x2100, "Variable", "global"), // MOVED
                        new SymbolSnapshot("g_added", 0x2200, "Variable", "global"), // ADDED
                        new SymbolSnapshot("poly", 0x2010, "Function", "global") // MODIFIED (type changed)
                ),
                List.of(), List.of(), List.of(), List.of()
        );

        FirmwareWorkspaceDiff diff = engine.compare(src, tgt);
        assertEquals(5, diff.symbols().size());
        assertEquals(4, diff.symbolDifferenceCount());

        SymbolDiffEntry poly = diff.symbols().stream()
                .filter(s -> s.symbolName().equals("poly")).findFirst().orElseThrow();
        assertEquals(DiffChangeKind.MODIFIED, poly.changeKind());
    }

    @Test
    void diffsStringsAndDetectsSecrets() throws Exception {
        WorkspaceSnapshot src = new WorkspaceSnapshot(
                "v1", List.of(), List.of(),
                List.of(
                        new StringSnapshot("Hello World", 0x3000, "ASCII", false),
                        new StringSnapshot("admin_secret_key=xyz", 0x3020, "UTF-8", true),
                        new StringSnapshot("Relocated text", 0x3040, "ASCII", false),
                        new StringSnapshot("Old banner", 0x3060, "ASCII", false)
                ),
                List.of(), List.of(), List.of()
        );

        WorkspaceSnapshot tgt = new WorkspaceSnapshot(
                "v2", List.of(), List.of(),
                List.of(
                        new StringSnapshot("Hello World", 0x3000, "ASCII", false), // UNCHANGED
                        new StringSnapshot("admin_secret_key=xyz", 0x3020, "UTF-8", true), // UNCHANGED, secret
                        new StringSnapshot("Relocated text", 0x3100, "ASCII", false), // MOVED
                        new StringSnapshot("New banner", 0x3200, "ASCII", false) // ADDED
                ),
                List.of(), List.of(), List.of()
        );

        FirmwareWorkspaceDiff diff = engine.compare(src, tgt);
        assertEquals(5, diff.strings().size());
        assertEquals(3, diff.stringDifferenceCount());

        StringDiffEntry secretEntry = diff.strings().stream()
                .filter(s -> s.stringValue().contains("admin_secret_key")).findFirst().orElseThrow();
        assertTrue(secretEntry.secret());
        assertEquals("[REDACTED_SECRET]", secretEntry.maskedValue(true));
        assertEquals("admin_secret_key=xyz", secretEntry.maskedValue(false));
    }

    @Test
    void diffsMetadataCorrectly() throws Exception {
        WorkspaceSnapshot src = new WorkspaceSnapshot(
                "v1", List.of(), List.of(), List.of(),
                List.of(
                        new MetadataSnapshot("Compiler", "GCC 12.2", false),
                        new MetadataSnapshot("Version", "1.0.0", false),
                        new MetadataSnapshot("ApiKey", "secret_12345", true),
                        new MetadataSnapshot("Deprecated", "true", false)
                ),
                List.of(), List.of()
        );

        WorkspaceSnapshot tgt = new WorkspaceSnapshot(
                "v2", List.of(), List.of(), List.of(),
                List.of(
                        new MetadataSnapshot("Compiler", "GCC 12.2", false), // UNCHANGED
                        new MetadataSnapshot("Version", "1.1.0", false), // MODIFIED
                        new MetadataSnapshot("ApiKey", "secret_99999", true), // MODIFIED secret
                        new MetadataSnapshot("BuildTarget", "ESP32-S3", false) // ADDED
                ),
                List.of(), List.of()
        );

        FirmwareWorkspaceDiff diff = engine.compare(src, tgt);
        assertEquals(5, diff.metadata().size());
        assertEquals(4, diff.metadataDifferenceCount());

        MetadataDiffEntry apiKey = diff.metadata().stream()
                .filter(m -> m.propertyKey().equals("ApiKey")).findFirst().orElseThrow();
        assertTrue(apiKey.secret());
        assertEquals("[REDACTED_SECRET]", apiKey.maskedSourceValue(true));
        assertEquals("secret_12345", apiKey.maskedSourceValue(false));
    }

    @Test
    void diffsMemoryBlocksCorrectly() throws Exception {
        WorkspaceSnapshot src = new WorkspaceSnapshot(
                "v1", List.of(), List.of(), List.of(), List.of(),
                List.of(
                        new MemoryBlockSnapshot(".text", 0x40000000, 0x10000, "RX", "hash_text_1"),
                        new MemoryBlockSnapshot(".data", 0x3ffb0000, 0x4000, "RW", "hash_data_1"),
                        new MemoryBlockSnapshot(".rodata", 0x3f400000, 0x8000, "R", "hash_rodata_1")
                ),
                List.of()
        );

        WorkspaceSnapshot tgt = new WorkspaceSnapshot(
                "v2", List.of(), List.of(), List.of(), List.of(),
                List.of(
                        new MemoryBlockSnapshot(".text", 0x40000000, 0x12000, "RX", "hash_text_2"), // MODIFIED
                        new MemoryBlockSnapshot(".data", 0x3ffb0000, 0x4000, "RW", "hash_data_1"), // UNCHANGED
                        new MemoryBlockSnapshot(".bss", 0x3ffc0000, 0x2000, "RW", "hash_bss_1") // ADDED
                ),
                List.of()
        );

        FirmwareWorkspaceDiff diff = engine.compare(src, tgt);
        assertEquals(4, diff.memoryBlocks().size());
        assertEquals(3, diff.memoryDifferenceCount());
    }

    @Test
    void diffsPartitionsCorrectly() throws Exception {
        WorkspaceSnapshot src = new WorkspaceSnapshot(
                "v1", List.of(), List.of(), List.of(), List.of(), List.of(),
                List.of(
                        new PartitionSnapshot("nvs", "data", "nvs", 0x9000, 0x6000, ""),
                        new PartitionSnapshot("factory", "app", "factory", 0x10000, 0x100000, ""),
                        new PartitionSnapshot("storage", "data", "spiffs", 0x110000, 0x100000, "")
                )
        );

        WorkspaceSnapshot tgt = new WorkspaceSnapshot(
                "v2", List.of(), List.of(), List.of(), List.of(), List.of(),
                List.of(
                        new PartitionSnapshot("nvs", "data", "nvs", 0x9000, 0x6000, ""), // UNCHANGED
                        new PartitionSnapshot("factory", "app", "factory", 0x10000, 0x180000, ""), // MODIFIED
                        new PartitionSnapshot("storage", "data", "spiffs", 0x190000, 0x100000, ""), // MOVED
                        new PartitionSnapshot("ota_data", "data", "ota", 0xe000, 0x2000, "") // ADDED
                )
        );

        FirmwareWorkspaceDiff diff = engine.compare(src, tgt);
        assertEquals(4, diff.partitions().size());
        assertEquals(3, diff.partitionDifferenceCount());
    }

    @Test
    void rejectsExceededObjectLimits() {
        ParserLimits strictLimits = new ParserLimits(1024, 1024, 1024, 2, 8, Duration.ofSeconds(10));
        WorkspaceSnapshot src = new WorkspaceSnapshot(
                "src",
                List.of(
                        new FunctionSnapshot("f1", 0x1000, 10, "h1", null),
                        new FunctionSnapshot("f2", 0x1010, 10, "h2", null)
                ),
                List.of(), List.of(), List.of(), List.of(), List.of()
        );
        WorkspaceSnapshot tgt = new WorkspaceSnapshot(
                "tgt",
                List.of(
                        new FunctionSnapshot("f3", 0x1020, 10, "h3", null)
                ),
                List.of(), List.of(), List.of(), List.of(), List.of()
        );

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                engine.compare(src, tgt, strictLimits, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void respectsCooperativeCancellation() {
        CancellationToken cancelledToken = () -> true;
        WorkspaceSnapshot empty = new WorkspaceSnapshot(
                "empty", List.of(), List.of(), List.of(), List.of(), List.of(), List.of());

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                engine.compare(empty, empty, ParserLimits.defaults(), cancelledToken));
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }
}
