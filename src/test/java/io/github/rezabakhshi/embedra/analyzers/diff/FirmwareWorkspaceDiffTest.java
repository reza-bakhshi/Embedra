package io.github.rezabakhshi.embedra.analyzers.diff;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FirmwareWorkspaceDiffTest {

    @Test
    void exportsJsonWithAndWithoutRedaction() {
        FirmwareWorkspaceDiff diff = new FirmwareWorkspaceDiff(
                "fw_v1", "fw_v2",
                List.of(new FunctionDiffEntry("main", DiffChangeKind.MODIFIED,
                        0x1000L, 0x1000L, 64L, 80L, "h1", "h2", "Size changed")),
                List.of(new SymbolDiffEntry("g_sym", "Variable", DiffChangeKind.ADDED,
                        null, 0x2000L, null, "global", "New symbol")),
                List.of(new StringDiffEntry("apiKey=supersecretpassword123", DiffChangeKind.ADDED,
                        null, 0x3000L, "ASCII", true, "Secret string")),
                List.of(new MetadataDiffEntry("db_password", DiffChangeKind.MODIFIED,
                        "secret_old", "secret_new", true, "Updated password")),
                List.of(new MemoryDiffEntry(".text", DiffChangeKind.UNCHANGED,
                        0x4000L, 0x4000L, 1024L, 1024L, "RX", "RX", "h", "h", "Identical")),
                List.of(new PartitionDiffEntry("nvs", DiffChangeKind.UNCHANGED,
                        "data", "nvs", 0x9000L, 0x9000L, 0x6000L, 0x6000L, "", "", "Identical"))
        );

        String redactedJson = diff.toJson(true);
        assertNotNull(redactedJson);
        assertTrue(redactedJson.contains("[REDACTED_SECRET]"));
        assertFalse(redactedJson.contains("supersecretpassword123"));
        assertFalse(redactedJson.contains("secret_old"));
        assertFalse(redactedJson.contains("secret_new"));

        String unredactedJson = diff.toJson(false);
        assertTrue(unredactedJson.contains("supersecretpassword123"));
        assertTrue(unredactedJson.contains("secret_old"));
        assertTrue(unredactedJson.contains("secret_new"));
    }

    @Test
    void exportsMarkdownWithStructuredTables() {
        FirmwareWorkspaceDiff diff = new FirmwareWorkspaceDiff(
                "app_v1", "app_v2",
                List.of(new FunctionDiffEntry("main", DiffChangeKind.MODIFIED,
                        0x1000L, 0x1000L, 64L, 80L, "h1", "h2", "Size changed")),
                List.of(),
                List.of(new StringDiffEntry("private_token=abc", DiffChangeKind.ADDED,
                        null, 0x3000L, "ASCII", true, "Secret")),
                List.of(),
                List.of(),
                List.of()
        );

        String md = diff.toMarkdown(true);
        assertTrue(md.contains("# Embedra Firmware Workspace Diff Report"));
        assertTrue(md.contains("## Functions"));
        assertTrue(md.contains("| `main` | Modified |"));
        assertTrue(md.contains("## Strings"));
        assertTrue(md.contains("[REDACTED_SECRET]"));
        assertFalse(md.contains("private_token=abc"));
    }

    @Test
    void exportsValidSarifReport() {
        FirmwareWorkspaceDiff diff = new FirmwareWorkspaceDiff(
                "src_img", "tgt_img",
                List.of(new FunctionDiffEntry("bad_func", DiffChangeKind.REMOVED,
                        0x1000L, null, 32L, 0L, "h", null, "Removed")),
                List.of(),
                List.of(new StringDiffEntry("auth_bearer=xyz", DiffChangeKind.ADDED,
                        null, 0x4000L, "ASCII", true, "Added token")),
                List.of(),
                List.of(),
                List.of()
        );

        String sarif = diff.toSarif(true);
        assertTrue(sarif.contains("\"version\": \"2.1.0\""));
        assertTrue(sarif.contains("\"name\": \"Embedra Workspace Diff\""));
        assertTrue(sarif.contains("\"results\": ["));
        assertTrue(sarif.contains("[REDACTED_SECRET]"));
        assertFalse(sarif.contains("auth_bearer=xyz"));
    }
}
