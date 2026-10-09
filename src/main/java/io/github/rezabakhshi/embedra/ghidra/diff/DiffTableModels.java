package io.github.rezabakhshi.embedra.ghidra.diff;

import io.github.rezabakhshi.embedra.analyzers.diff.DiffChangeKind;
import io.github.rezabakhshi.embedra.analyzers.diff.FunctionDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.MemoryDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.MetadataDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.PartitionDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.StringDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.SymbolDiffEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Swing TableModels for the 6 firmware diff views with filtering and secret redaction.
 */
public final class DiffTableModels {

    private DiffTableModels() {
    }

    @SuppressWarnings("serial")
    public static class FunctionTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private static final String[] COLS = {
                "Change", "Function Name", "Source Addr", "Target Addr", "Source Size", "Target Size", "Details"
        };

        private final List<FunctionDiffEntry> allEntries = new ArrayList<>();

        private final List<FunctionDiffEntry> visibleEntries = new ArrayList<>();

        private DiffChangeKind kindFilter;

        private String textFilter = "";

        public void setEntries(List<FunctionDiffEntry> entries) {
            allEntries.clear();
            if (entries != null) {
                allEntries.addAll(entries);
            }
            applyFilters();
        }

        public void setFilters(DiffChangeKind kind, String text) {
            this.kindFilter = kind;
            this.textFilter = text != null ? text.trim().toLowerCase(Locale.ROOT) : "";
            applyFilters();
        }

        private void applyFilters() {
            visibleEntries.clear();
            for (FunctionDiffEntry e : allEntries) {
                if (kindFilter != null && e.changeKind() != kindFilter) {
                    continue;
                }
                if (!textFilter.isEmpty() && !e.functionName().toLowerCase(Locale.ROOT).contains(textFilter)
                        && !e.details().toLowerCase(Locale.ROOT).contains(textFilter)) {
                    continue;
                }
                visibleEntries.add(e);
            }
            fireTableDataChanged();
        }

        public FunctionDiffEntry getEntryAt(int row) {
            if (row >= 0 && row < visibleEntries.size()) {
                return visibleEntries.get(row);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return visibleEntries.size();
        }

        @Override
        public int getColumnCount() {
            return COLS.length;
        }

        @Override
        public String getColumnName(int col) {
            return COLS[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            FunctionDiffEntry e = visibleEntries.get(row);
            return switch (col) {
                case 0 -> e.changeKind();
                case 1 -> e.functionName();
                case 2 -> e.sourceAddress() != null ? String.format("0x%x", e.sourceAddress()) : "-";
                case 3 -> e.targetAddress() != null ? String.format("0x%x", e.targetAddress()) : "-";
                case 4 -> e.sourceLength() > 0 ? String.valueOf(e.sourceLength()) : "-";
                case 5 -> e.targetLength() > 0 ? String.valueOf(e.targetLength()) : "-";
                case 6 -> e.details();
                default -> "";
            };
        }
    }

    @SuppressWarnings("serial")
    public static class SymbolTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private static final String[] COLS = {
                "Change", "Symbol Name", "Type", "Source Addr", "Target Addr", "Namespace", "Details"
        };

        private final List<SymbolDiffEntry> allEntries = new ArrayList<>();

        private final List<SymbolDiffEntry> visibleEntries = new ArrayList<>();

        private DiffChangeKind kindFilter;

        private String textFilter = "";

        public void setEntries(List<SymbolDiffEntry> entries) {
            allEntries.clear();
            if (entries != null) {
                allEntries.addAll(entries);
            }
            applyFilters();
        }

        public void setFilters(DiffChangeKind kind, String text) {
            this.kindFilter = kind;
            this.textFilter = text != null ? text.trim().toLowerCase(Locale.ROOT) : "";
            applyFilters();
        }

        private void applyFilters() {
            visibleEntries.clear();
            for (SymbolDiffEntry e : allEntries) {
                if (kindFilter != null && e.changeKind() != kindFilter) {
                    continue;
                }
                if (!textFilter.isEmpty() && !e.symbolName().toLowerCase(Locale.ROOT).contains(textFilter)
                        && !e.details().toLowerCase(Locale.ROOT).contains(textFilter)) {
                    continue;
                }
                visibleEntries.add(e);
            }
            fireTableDataChanged();
        }

        public SymbolDiffEntry getEntryAt(int row) {
            if (row >= 0 && row < visibleEntries.size()) {
                return visibleEntries.get(row);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return visibleEntries.size();
        }

        @Override
        public int getColumnCount() {
            return COLS.length;
        }

        @Override
        public String getColumnName(int col) {
            return COLS[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            SymbolDiffEntry e = visibleEntries.get(row);
            return switch (col) {
                case 0 -> e.changeKind();
                case 1 -> e.symbolName();
                case 2 -> e.symbolType();
                case 3 -> e.sourceAddress() != null ? String.format("0x%x", e.sourceAddress()) : "-";
                case 4 -> e.targetAddress() != null ? String.format("0x%x", e.targetAddress()) : "-";
                case 5 -> {
                    if (e.sourceNamespace() != null) {
                        yield e.sourceNamespace();
                    }
                    yield e.targetNamespace() != null ? e.targetNamespace() : "-";
                }
                case 6 -> e.details();
                default -> "";
            };
        }
    }

    @SuppressWarnings("serial")
    public static class StringTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private static final String[] COLS = {
                "Change", "String Value", "Source Addr", "Target Addr", "Encoding", "Secret?", "Details"
        };

        private final List<StringDiffEntry> allEntries = new ArrayList<>();

        private final List<StringDiffEntry> visibleEntries = new ArrayList<>();

        private DiffChangeKind kindFilter;

        private String textFilter = "";

        private boolean redactSecrets = true;

        public void setEntries(List<StringDiffEntry> entries) {
            allEntries.clear();
            if (entries != null) {
                allEntries.addAll(entries);
            }
            applyFilters();
        }

        public void setRedactSecrets(boolean redact) {
            this.redactSecrets = redact;
            fireTableDataChanged();
        }

        public void setFilters(DiffChangeKind kind, String text) {
            this.kindFilter = kind;
            this.textFilter = text != null ? text.trim().toLowerCase(Locale.ROOT) : "";
            applyFilters();
        }

        private void applyFilters() {
            visibleEntries.clear();
            for (StringDiffEntry e : allEntries) {
                if (kindFilter != null && e.changeKind() != kindFilter) {
                    continue;
                }
                if (!textFilter.isEmpty() && !e.stringValue().toLowerCase(Locale.ROOT).contains(textFilter)
                        && !e.details().toLowerCase(Locale.ROOT).contains(textFilter)) {
                    continue;
                }
                visibleEntries.add(e);
            }
            fireTableDataChanged();
        }

        public StringDiffEntry getEntryAt(int row) {
            if (row >= 0 && row < visibleEntries.size()) {
                return visibleEntries.get(row);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return visibleEntries.size();
        }

        @Override
        public int getColumnCount() {
            return COLS.length;
        }

        @Override
        public String getColumnName(int col) {
            return COLS[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            StringDiffEntry e = visibleEntries.get(row);
            return switch (col) {
                case 0 -> e.changeKind();
                case 1 -> e.maskedValue(redactSecrets);
                case 2 -> e.sourceAddress() != null ? String.format("0x%x", e.sourceAddress()) : "-";
                case 3 -> e.targetAddress() != null ? String.format("0x%x", e.targetAddress()) : "-";
                case 4 -> e.encoding();
                case 5 -> e.secret() ? "YES" : "No";
                case 6 -> e.details();
                default -> "";
            };
        }
    }

    @SuppressWarnings("serial")
    public static class MetadataTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private static final String[] COLS = {
                "Change", "Property Key", "Source Value", "Target Value", "Secret?", "Details"
        };

        private final List<MetadataDiffEntry> allEntries = new ArrayList<>();

        private final List<MetadataDiffEntry> visibleEntries = new ArrayList<>();

        private DiffChangeKind kindFilter;

        private String textFilter = "";

        private boolean redactSecrets = true;

        public void setEntries(List<MetadataDiffEntry> entries) {
            allEntries.clear();
            if (entries != null) {
                allEntries.addAll(entries);
            }
            applyFilters();
        }

        public void setRedactSecrets(boolean redact) {
            this.redactSecrets = redact;
            fireTableDataChanged();
        }

        public void setFilters(DiffChangeKind kind, String text) {
            this.kindFilter = kind;
            this.textFilter = text != null ? text.trim().toLowerCase(Locale.ROOT) : "";
            applyFilters();
        }

        private void applyFilters() {
            visibleEntries.clear();
            for (MetadataDiffEntry e : allEntries) {
                if (kindFilter != null && e.changeKind() != kindFilter) {
                    continue;
                }
                if (!textFilter.isEmpty() && !e.propertyKey().toLowerCase(Locale.ROOT).contains(textFilter)
                        && !e.details().toLowerCase(Locale.ROOT).contains(textFilter)) {
                    continue;
                }
                visibleEntries.add(e);
            }
            fireTableDataChanged();
        }

        public MetadataDiffEntry getEntryAt(int row) {
            if (row >= 0 && row < visibleEntries.size()) {
                return visibleEntries.get(row);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return visibleEntries.size();
        }

        @Override
        public int getColumnCount() {
            return COLS.length;
        }

        @Override
        public String getColumnName(int col) {
            return COLS[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            MetadataDiffEntry e = visibleEntries.get(row);
            return switch (col) {
                case 0 -> e.changeKind();
                case 1 -> e.propertyKey();
                case 2 -> formatMetaValue(e.sourceValue(), e.secret());
                case 3 -> formatMetaValue(e.targetValue(), e.secret());
                case 4 -> e.secret() ? "YES" : "No";
                case 5 -> e.details();
                default -> "";
            };
        }

        private String formatMetaValue(String value, boolean secret) {
            if (value == null) {
                return "-";
            }
            if (secret && redactSecrets) {
                return "[REDACTED_SECRET]";
            }
            return value;
        }
    }

    @SuppressWarnings("serial")
    public static class MemoryTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private static final String[] COLS = {
                "Change", "Block Name", "Source Addr", "Target Addr",
                "Source Size", "Target Size", "Permissions", "Details"
        };

        private final List<MemoryDiffEntry> allEntries = new ArrayList<>();

        private final List<MemoryDiffEntry> visibleEntries = new ArrayList<>();

        private DiffChangeKind kindFilter;

        private String textFilter = "";

        public void setEntries(List<MemoryDiffEntry> entries) {
            allEntries.clear();
            if (entries != null) {
                allEntries.addAll(entries);
            }
            applyFilters();
        }

        public void setFilters(DiffChangeKind kind, String text) {
            this.kindFilter = kind;
            this.textFilter = text != null ? text.trim().toLowerCase(Locale.ROOT) : "";
            applyFilters();
        }

        private void applyFilters() {
            visibleEntries.clear();
            for (MemoryDiffEntry e : allEntries) {
                if (kindFilter != null && e.changeKind() != kindFilter) {
                    continue;
                }
                if (!textFilter.isEmpty() && !e.blockName().toLowerCase(Locale.ROOT).contains(textFilter)
                        && !e.details().toLowerCase(Locale.ROOT).contains(textFilter)) {
                    continue;
                }
                visibleEntries.add(e);
            }
            fireTableDataChanged();
        }

        public MemoryDiffEntry getEntryAt(int row) {
            if (row >= 0 && row < visibleEntries.size()) {
                return visibleEntries.get(row);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return visibleEntries.size();
        }

        @Override
        public int getColumnCount() {
            return COLS.length;
        }

        @Override
        public String getColumnName(int col) {
            return COLS[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            MemoryDiffEntry e = visibleEntries.get(row);
            return switch (col) {
                case 0 -> e.changeKind();
                case 1 -> e.blockName();
                case 2 -> e.sourceAddress() != null ? String.format("0x%x", e.sourceAddress()) : "-";
                case 3 -> e.targetAddress() != null ? String.format("0x%x", e.targetAddress()) : "-";
                case 4 -> e.sourceSize() > 0 ? String.valueOf(e.sourceSize()) : "-";
                case 5 -> e.targetSize() > 0 ? String.valueOf(e.targetSize()) : "-";
                case 6 -> {
                    if (e.sourcePermissions() != null && !e.sourcePermissions().isEmpty()) {
                        yield e.sourcePermissions();
                    }
                    yield e.targetPermissions() != null ? e.targetPermissions() : "-";
                }
                case 7 -> e.details();
                default -> "";
            };
        }
    }

    @SuppressWarnings("serial")
    public static class PartitionTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private static final String[] COLS = {
                "Change", "Partition Name", "Type/Subtype", "Source Offset",
                "Target Offset", "Source Size", "Target Size", "Flags", "Details"
        };

        private final List<PartitionDiffEntry> allEntries = new ArrayList<>();

        private final List<PartitionDiffEntry> visibleEntries = new ArrayList<>();

        private DiffChangeKind kindFilter;

        private String textFilter = "";

        public void setEntries(List<PartitionDiffEntry> entries) {
            allEntries.clear();
            if (entries != null) {
                allEntries.addAll(entries);
            }
            applyFilters();
        }

        public void setFilters(DiffChangeKind kind, String text) {
            this.kindFilter = kind;
            this.textFilter = text != null ? text.trim().toLowerCase(Locale.ROOT) : "";
            applyFilters();
        }

        private void applyFilters() {
            visibleEntries.clear();
            for (PartitionDiffEntry e : allEntries) {
                if (kindFilter != null && e.changeKind() != kindFilter) {
                    continue;
                }
                if (!textFilter.isEmpty() && !e.partitionName().toLowerCase(Locale.ROOT).contains(textFilter)
                        && !e.details().toLowerCase(Locale.ROOT).contains(textFilter)) {
                    continue;
                }
                visibleEntries.add(e);
            }
            fireTableDataChanged();
        }

        public PartitionDiffEntry getEntryAt(int row) {
            if (row >= 0 && row < visibleEntries.size()) {
                return visibleEntries.get(row);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return visibleEntries.size();
        }

        @Override
        public int getColumnCount() {
            return COLS.length;
        }

        @Override
        public String getColumnName(int col) {
            return COLS[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            PartitionDiffEntry e = visibleEntries.get(row);
            return switch (col) {
                case 0 -> e.changeKind();
                case 1 -> e.partitionName();
                case 2 -> e.partitionType() + "/"
                        + (e.partitionSubtype() != null ? e.partitionSubtype() : "-");
                case 3 -> e.sourceOffset() != null ? String.format("0x%x", e.sourceOffset()) : "-";
                case 4 -> e.targetOffset() != null ? String.format("0x%x", e.targetOffset()) : "-";
                case 5 -> e.sourceSize() > 0 ? String.valueOf(e.sourceSize()) : "-";
                case 6 -> e.targetSize() > 0 ? String.valueOf(e.targetSize()) : "-";
                case 7 -> {
                    if (!e.sourceFlags().isEmpty()) {
                        yield e.sourceFlags();
                    }
                    yield !e.targetFlags().isEmpty() ? e.targetFlags() : "-";
                }
                case 8 -> e.details();
                default -> "";
            };
        }
    }
}
