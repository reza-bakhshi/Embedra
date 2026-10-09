package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Aggregated multi-view comparison between two firmware workspaces (T062, AN-006, AN-008).
 *
 * <p>Encompasses function, symbol, string, metadata, memory, and partition views.</p>
 */
public record FirmwareWorkspaceDiff(
        String sourceWorkspaceName,
        String targetWorkspaceName,
        List<FunctionDiffEntry> functionDiffs,
        List<SymbolDiffEntry> symbolDiffs,
        List<StringDiffEntry> stringDiffs,
        List<MetadataDiffEntry> metadataDiffs,
        List<MemoryDiffEntry> memoryDiffs,
        List<PartitionDiffEntry> partitionDiffs) {

    private static final Pattern SENSITIVE_PATTERN = Pattern.compile(
            "(?i)(password|secret|token|api[_-]?key|credential|private[_-]?key|auth)"
                    + "([:=]|\\s+is\\s+|\\s+as\\s+)?\\s*([A-Za-z0-9+/=_-]{4,})");

    public FirmwareWorkspaceDiff {
        Objects.requireNonNull(sourceWorkspaceName, "sourceWorkspaceName must not be null");
        Objects.requireNonNull(targetWorkspaceName, "targetWorkspaceName must not be null");
        functionDiffs = functionDiffs == null ? List.of() : Collections.unmodifiableList(List.copyOf(functionDiffs));
        symbolDiffs = symbolDiffs == null ? List.of() : Collections.unmodifiableList(List.copyOf(symbolDiffs));
        stringDiffs = stringDiffs == null ? List.of() : Collections.unmodifiableList(List.copyOf(stringDiffs));
        metadataDiffs = metadataDiffs == null ? List.of() : Collections.unmodifiableList(List.copyOf(metadataDiffs));
        memoryDiffs = memoryDiffs == null ? List.of() : Collections.unmodifiableList(List.copyOf(memoryDiffs));
        partitionDiffs = partitionDiffs == null
                ? List.of() : Collections.unmodifiableList(List.copyOf(partitionDiffs));
    }

    public int totalDifferences() {
        return functionDifferenceCount() + symbolDifferenceCount() + stringDifferenceCount()
                + metadataDifferenceCount() + memoryDifferenceCount() + partitionDifferenceCount();
    }

    public int totalItems() {
        return functionDiffs.size() + symbolDiffs.size() + stringDiffs.size()
                + metadataDiffs.size() + memoryDiffs.size() + partitionDiffs.size();
    }

    public int functionDifferenceCount() {
        return (int) functionDiffs.stream().filter(e -> e.changeKind().isDifference()).count();
    }

    public int symbolDifferenceCount() {
        return (int) symbolDiffs.stream().filter(e -> e.changeKind().isDifference()).count();
    }

    public int stringDifferenceCount() {
        return (int) stringDiffs.stream().filter(e -> e.changeKind().isDifference()).count();
    }

    public int metadataDifferenceCount() {
        return (int) metadataDiffs.stream().filter(e -> e.changeKind().isDifference()).count();
    }

    public String sourceWorkspace() {
        return sourceWorkspaceName;
    }

    public String targetWorkspace() {
        return targetWorkspaceName;
    }

    public List<FunctionDiffEntry> functions() {
        return functionDiffs;
    }

    public List<SymbolDiffEntry> symbols() {
        return symbolDiffs;
    }

    public List<StringDiffEntry> strings() {
        return stringDiffs;
    }

    public List<MetadataDiffEntry> metadata() {
        return metadataDiffs;
    }

    public List<MemoryDiffEntry> memoryBlocks() {
        return memoryDiffs;
    }

    public List<PartitionDiffEntry> partitions() {
        return partitionDiffs;
    }

    public int memoryDifferenceCount() {
        return (int) memoryDiffs.stream().filter(e -> e.changeKind().isDifference()).count();
    }

    public int partitionDifferenceCount() {
        return (int) partitionDiffs.stream().filter(e -> e.changeKind().isDifference()).count();
    }

    public int countByKind(DiffChangeKind kind) {
        int count = 0;
        count += (int) functionDiffs.stream().filter(e -> e.changeKind() == kind).count();
        count += (int) symbolDiffs.stream().filter(e -> e.changeKind() == kind).count();
        count += (int) stringDiffs.stream().filter(e -> e.changeKind() == kind).count();
        count += (int) metadataDiffs.stream().filter(e -> e.changeKind() == kind).count();
        count += (int) memoryDiffs.stream().filter(e -> e.changeKind() == kind).count();
        count += (int) partitionDiffs.stream().filter(e -> e.changeKind() == kind).count();
        return count;
    }

    public String toJson(boolean redactSecrets) {
        return toJson(redactSecrets, false);
    }

    /**
     * Serializes the multi-view workspace diff to JSON (AN-008).
     */
    public String toJson(boolean redactSecrets, boolean changesOnly) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"sourceWorkspace\": \"").append(escapeJson(sourceWorkspaceName)).append("\",\n");
        sb.append("  \"targetWorkspace\": \"").append(escapeJson(targetWorkspaceName)).append("\",\n");
        sb.append("  \"totalDifferences\": ").append(totalDifferences()).append(",\n");
        sb.append("  \"totalItems\": ").append(totalItems()).append(",\n");
        sb.append("  \"added\": ").append(countByKind(DiffChangeKind.ADDED)).append(",\n");
        sb.append("  \"removed\": ").append(countByKind(DiffChangeKind.REMOVED)).append(",\n");
        sb.append("  \"modified\": ").append(countByKind(DiffChangeKind.MODIFIED)).append(",\n");
        sb.append("  \"moved\": ").append(countByKind(DiffChangeKind.MOVED)).append(",\n");
        sb.append("  \"unchanged\": ").append(countByKind(DiffChangeKind.UNCHANGED)).append(",\n");

        // Functions
        List<FunctionDiffEntry> fList = changesOnly
                ? functionDiffs.stream().filter(e -> e.changeKind().isDifference()).toList() : functionDiffs;
        sb.append("  \"functions\": [\n");
        for (int i = 0; i < fList.size(); i++) {
            FunctionDiffEntry e = fList.get(i);
            sb.append("    {\n");
            sb.append("      \"name\": \"").append(escapeJson(e.functionName())).append("\",\n");
            sb.append("      \"changeKind\": \"").append(e.changeKind().name()).append("\",\n");
            sb.append("      \"sourceAddress\": ").append(e.sourceAddress()).append(",\n");
            sb.append("      \"targetAddress\": ").append(e.targetAddress()).append(",\n");
            sb.append("      \"sourceLength\": ").append(e.sourceLength()).append(",\n");
            sb.append("      \"targetLength\": ").append(e.targetLength()).append(",\n");
            sb.append("      \"details\": \"").append(escapeJson(e.details())).append("\"\n");
            sb.append("    }").append(i < fList.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        // Symbols
        List<SymbolDiffEntry> sList = changesOnly
                ? symbolDiffs.stream().filter(e -> e.changeKind().isDifference()).toList() : symbolDiffs;
        sb.append("  \"symbols\": [\n");
        for (int i = 0; i < sList.size(); i++) {
            SymbolDiffEntry e = sList.get(i);
            sb.append("    {\n");
            sb.append("      \"name\": \"").append(escapeJson(e.symbolName())).append("\",\n");
            sb.append("      \"type\": \"").append(escapeJson(e.symbolType())).append("\",\n");
            sb.append("      \"changeKind\": \"").append(e.changeKind().name()).append("\",\n");
            sb.append("      \"sourceAddress\": ").append(e.sourceAddress()).append(",\n");
            sb.append("      \"targetAddress\": ").append(e.targetAddress()).append(",\n");
            sb.append("      \"details\": \"").append(escapeJson(e.details())).append("\"\n");
            sb.append("    }").append(i < sList.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        // Strings
        List<StringDiffEntry> strList = changesOnly
                ? stringDiffs.stream().filter(e -> e.changeKind().isDifference()).toList() : stringDiffs;
        sb.append("  \"strings\": [\n");
        for (int i = 0; i < strList.size(); i++) {
            StringDiffEntry e = strList.get(i);
            String val = e.maskedValue(redactSecrets);
            sb.append("    {\n");
            sb.append("      \"value\": \"").append(escapeJson(val)).append("\",\n");
            sb.append("      \"changeKind\": \"").append(e.changeKind().name()).append("\",\n");
            sb.append("      \"sourceAddress\": ").append(e.sourceAddress()).append(",\n");
            sb.append("      \"targetAddress\": ").append(e.targetAddress()).append(",\n");
            sb.append("      \"secret\": ").append(e.secret()).append(",\n");
            sb.append("      \"details\": \"").append(escapeJson(e.details())).append("\"\n");
            sb.append("    }").append(i < strList.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        // Metadata
        List<MetadataDiffEntry> mList = changesOnly
                ? metadataDiffs.stream().filter(e -> e.changeKind().isDifference()).toList() : metadataDiffs;
        sb.append("  \"metadata\": [\n");
        for (int i = 0; i < mList.size(); i++) {
            MetadataDiffEntry e = mList.get(i);
            String sVal = e.maskedSourceValue(redactSecrets);
            String tVal = e.maskedTargetValue(redactSecrets);
            sb.append("    {\n");
            sb.append("      \"key\": \"").append(escapeJson(e.propertyKey())).append("\",\n");
            sb.append("      \"changeKind\": \"").append(e.changeKind().name()).append("\",\n");
            sb.append("      \"sourceValue\": ").append(sVal == null ? "null" : "\"" + escapeJson(sVal) + "\"")
                    .append(",\n");
            sb.append("      \"targetValue\": ").append(tVal == null ? "null" : "\"" + escapeJson(tVal) + "\"")
                    .append(",\n");
            sb.append("      \"details\": \"").append(escapeJson(e.details())).append("\"\n");
            sb.append("    }").append(i < mList.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        // Memory
        List<MemoryDiffEntry> memList = changesOnly
                ? memoryDiffs.stream().filter(e -> e.changeKind().isDifference()).toList() : memoryDiffs;
        sb.append("  \"memory\": [\n");
        for (int i = 0; i < memList.size(); i++) {
            MemoryDiffEntry e = memList.get(i);
            sb.append("    {\n");
            sb.append("      \"name\": \"").append(escapeJson(e.blockName())).append("\",\n");
            sb.append("      \"changeKind\": \"").append(e.changeKind().name()).append("\",\n");
            sb.append("      \"sourceAddress\": ").append(e.sourceAddress()).append(",\n");
            sb.append("      \"targetAddress\": ").append(e.targetAddress()).append(",\n");
            sb.append("      \"sourceSize\": ").append(e.sourceSize()).append(",\n");
            sb.append("      \"targetSize\": ").append(e.targetSize()).append(",\n");
            sb.append("      \"details\": \"").append(escapeJson(e.details())).append("\"\n");
            sb.append("    }").append(i < memList.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        // Partitions
        List<PartitionDiffEntry> pList = changesOnly
                ? partitionDiffs.stream().filter(e -> e.changeKind().isDifference()).toList() : partitionDiffs;
        sb.append("  \"partitions\": [\n");
        for (int i = 0; i < pList.size(); i++) {
            PartitionDiffEntry e = pList.get(i);
            sb.append("    {\n");
            sb.append("      \"name\": \"").append(escapeJson(e.partitionName())).append("\",\n");
            sb.append("      \"changeKind\": \"").append(e.changeKind().name()).append("\",\n");
            sb.append("      \"type\": \"").append(escapeJson(e.partitionType())).append("\",\n");
            sb.append("      \"sourceOffset\": ").append(e.sourceOffset()).append(",\n");
            sb.append("      \"targetOffset\": ").append(e.targetOffset()).append(",\n");
            sb.append("      \"details\": \"").append(escapeJson(e.details())).append("\"\n");
            sb.append("    }").append(i < pList.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");

        return sb.toString();
    }

    public String toMarkdown(boolean redactSecrets) {
        return toMarkdown(redactSecrets, false);
    }

    /**
     * Serializes the multi-view workspace diff to Markdown tables (T062, AN-008).
     */
    public String toMarkdown(boolean redactSecrets, boolean changesOnly) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Embedra Firmware Workspace Diff Report (T062)\n\n");
        sb.append("**Source**: `").append(sourceWorkspaceName).append("` | ")
                .append("**Target**: `").append(targetWorkspaceName).append("`\n\n");

        sb.append("| Total Differences | Added | Removed | Modified | Moved | Unchanged |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
        sb.append("| ").append(totalDifferences())
                .append(" | ").append(countByKind(DiffChangeKind.ADDED))
                .append(" | ").append(countByKind(DiffChangeKind.REMOVED))
                .append(" | ").append(countByKind(DiffChangeKind.MODIFIED))
                .append(" | ").append(countByKind(DiffChangeKind.MOVED))
                .append(" | ").append(countByKind(DiffChangeKind.UNCHANGED))
                .append(" |\n\n");

        // Functions
        List<FunctionDiffEntry> fList = changesOnly
                ? functionDiffs.stream().filter(e -> e.changeKind().isDifference()).toList() : functionDiffs;
        sb.append("## Functions (").append(fList.size()).append(")\n\n");
        sb.append("| Function | Change | Source Addr | Target Addr | Source Size | Target Size | Details |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for (FunctionDiffEntry e : fList) {
            String sAddr = e.sourceAddress() == null ? "-" : "0x" + Long.toHexString(e.sourceAddress());
            String tAddr = e.targetAddress() == null ? "-" : "0x" + Long.toHexString(e.targetAddress());
            sb.append("| `").append(e.functionName()).append("` | ")
                    .append(e.changeKind().displayName()).append(" | ")
                    .append(sAddr).append(" | ")
                    .append(tAddr).append(" | ")
                    .append(e.sourceLength()).append(" | ")
                    .append(e.targetLength()).append(" | ")
                    .append(e.details().replace("|", "\\|")).append(" |\n");
        }
        sb.append("\n");

        // Strings
        List<StringDiffEntry> strList = changesOnly
                ? stringDiffs.stream().filter(e -> e.changeKind().isDifference()).toList() : stringDiffs;
        sb.append("## Strings (").append(strList.size()).append(")\n\n");
        sb.append("| String | Change | Source Addr | Target Addr | Encoding | Details |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for (StringDiffEntry e : strList) {
            String val = e.maskedValue(redactSecrets);
            String sAddr = e.sourceAddress() == null ? "-" : "0x" + Long.toHexString(e.sourceAddress());
            String tAddr = e.targetAddress() == null ? "-" : "0x" + Long.toHexString(e.targetAddress());
            sb.append("| `").append(val.replace("`", "'")).append("` | ")
                    .append(e.changeKind().displayName()).append(" | ")
                    .append(sAddr).append(" | ")
                    .append(tAddr).append(" | ")
                    .append(e.encoding()).append(" | ")
                    .append(e.details().replace("|", "\\|")).append(" |\n");
        }
        sb.append("\n");

        return sb.toString();
    }

    /**
     * Serializes diff changes to SARIF 2.1.0 format.
     */
    public String toSarif(boolean redactSecrets) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
        sb.append("  \"version\": \"2.1.0\",\n");
        sb.append("  \"runs\": [\n");
        sb.append("    {\n");
        sb.append("      \"tool\": {\n");
        sb.append("        \"driver\": {\n");
        sb.append("          \"name\": \"Embedra Workspace Diff\",\n");
        sb.append("          \"version\": \"1.0.0\"\n");
        sb.append("        }\n");
        sb.append("      },\n");
        sb.append("      \"results\": [\n");

        List<String> resultBlocks = new ArrayList<>();

        for (FunctionDiffEntry f : functionDiffs) {
            if (!f.changeKind().isDifference()) {
                continue;
            }
            long addr = f.targetAddress() != null ? f.targetAddress()
                    : (f.sourceAddress() != null ? f.sourceAddress() : 0L);
            resultBlocks.add(String.format("""
                    {
                      "ruleId": "EMBEDRA-DIFF-FUNCTION-%s",
                      "level": "note",
                      "message": {
                        "text": "Function %s %s: %s"
                      },
                      "locations": [
                        {
                          "physicalLocation": {
                            "address": {
                              "absoluteAddress": %d
                            }
                          }
                        }
                      ]
                    }""", f.changeKind().name(), escapeJson(f.functionName()),
                    f.changeKind().displayName(), escapeJson(f.details()), addr));
        }

        for (SymbolDiffEntry s : symbolDiffs) {
            if (!s.changeKind().isDifference()) {
                continue;
            }
            long addr = s.targetAddress() != null ? s.targetAddress()
                    : (s.sourceAddress() != null ? s.sourceAddress() : 0L);
            resultBlocks.add(String.format("""
                    {
                      "ruleId": "EMBEDRA-DIFF-SYMBOL-%s",
                      "level": "note",
                      "message": {
                        "text": "Symbol %s %s: %s"
                      },
                      "locations": [
                        {
                          "physicalLocation": {
                            "address": {
                              "absoluteAddress": %d
                            }
                          }
                        }
                      ]
                    }""", s.changeKind().name(), escapeJson(s.symbolName()),
                    s.changeKind().displayName(), escapeJson(s.details()), addr));
        }

        for (StringDiffEntry s : stringDiffs) {
            if (!s.changeKind().isDifference()) {
                continue;
            }
            long addr = s.targetAddress() != null ? s.targetAddress()
                    : (s.sourceAddress() != null ? s.sourceAddress() : 0L);
            String val = s.maskedValue(redactSecrets);
            resultBlocks.add(String.format("""
                    {
                      "ruleId": "EMBEDRA-DIFF-STRING-%s",
                      "level": "note",
                      "message": {
                        "text": "String '%s' %s: %s"
                      },
                      "locations": [
                        {
                          "physicalLocation": {
                            "address": {
                              "absoluteAddress": %d
                            }
                          }
                        }
                      ]
                    }""", s.changeKind().name(), escapeJson(val),
                    s.changeKind().displayName(), escapeJson(s.details()), addr));
        }

        for (MetadataDiffEntry m : metadataDiffs) {
            if (!m.changeKind().isDifference()) {
                continue;
            }
            String val = m.maskedTargetValue(redactSecrets);
            resultBlocks.add(String.format("""
                    {
                      "ruleId": "EMBEDRA-DIFF-METADATA-%s",
                      "level": "note",
                      "message": {
                        "text": "Metadata '%s' %s: %s"
                      }
                    }""", m.changeKind().name(), escapeJson(m.propertyKey()),
                    m.changeKind().displayName(), escapeJson(val != null ? val : m.details())));
        }

        for (MemoryDiffEntry m : memoryDiffs) {
            if (!m.changeKind().isDifference()) {
                continue;
            }
            long addr = m.targetAddress() != null ? m.targetAddress()
                    : (m.sourceAddress() != null ? m.sourceAddress() : 0L);
            resultBlocks.add(String.format("""
                    {
                      "ruleId": "EMBEDRA-DIFF-MEMORY-%s",
                      "level": "note",
                      "message": {
                        "text": "Memory block %s %s: %s"
                      },
                      "locations": [
                        {
                          "physicalLocation": {
                            "address": {
                              "absoluteAddress": %d
                            }
                          }
                        }
                      ]
                    }""", m.changeKind().name(), escapeJson(m.blockName()),
                    m.changeKind().displayName(), escapeJson(m.details()), addr));
        }

        for (PartitionDiffEntry p : partitionDiffs) {
            if (!p.changeKind().isDifference()) {
                continue;
            }
            long offset = p.targetOffset() != null ? p.targetOffset()
                    : (p.sourceOffset() != null ? p.sourceOffset() : 0L);
            resultBlocks.add(String.format("""
                    {
                      "ruleId": "EMBEDRA-DIFF-PARTITION-%s",
                      "level": "note",
                      "message": {
                        "text": "Partition %s %s: %s"
                      },
                      "locations": [
                        {
                          "physicalLocation": {
                            "address": {
                              "absoluteAddress": %d
                            }
                          }
                        }
                      ]
                    }""", p.changeKind().name(), escapeJson(p.partitionName()),
                    p.changeKind().displayName(), escapeJson(p.details()), offset));
        }

        for (int i = 0; i < resultBlocks.size(); i++) {
            sb.append("        ").append(resultBlocks.get(i).replace("\n", "\n        "));
            if (i < resultBlocks.size() - 1) {
                sb.append(",");
            }
            sb.append("\n");
        }

        sb.append("      ]\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");

        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
