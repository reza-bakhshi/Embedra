package io.github.rezabakhshi.embedra.ghidra.findings;

import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFinding;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import javax.swing.table.AbstractTableModel;

/**
 * Swing table model for the Embedra sortable findings panel (AN-006).
 */
@SuppressWarnings("serial")
public final class FindingsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    public static final int COL_SEVERITY = 0;

    public static final int COL_CONFIDENCE = 1;

    public static final int COL_CATEGORY = 2;

    public static final int COL_ADDRESS = 3;

    public static final int COL_TARGET = 4;

    public static final int COL_PLATFORM = 5;

    public static final int COL_STATUS = 6;

    public static final int COL_EXPLANATION = 7;

    private static final String[] COLUMN_NAMES = {
        "Severity", "Confidence", "Category", "Address", "Target", "Platform", "Status", "Explanation"
    };

    private final List<UnifiedFinding> allFindings = new ArrayList<>();

    private final List<UnifiedFinding> filteredFindings = new ArrayList<>();

    private boolean redactSecrets = true;

    private boolean showSuppressed = true;

    private String textFilter = "";

    private FindingCategory categoryFilter;

    private FindingSeverity severityFilter;

    public FindingsTableModel() {
    }

    public void setFindings(List<UnifiedFinding> findings) {
        Objects.requireNonNull(findings, "findings must not be null");
        allFindings.clear();
        allFindings.addAll(findings);
        applyFilters();
    }

    public List<UnifiedFinding> getAllFindings() {
        return Collections.unmodifiableList(new ArrayList<>(allFindings));
    }

    public UnifiedFinding getFindingAt(int row) {
        if (row >= 0 && row < filteredFindings.size()) {
            return filteredFindings.get(row);
        }
        return null;
    }

    public void setRedactSecrets(boolean redact) {
        if (this.redactSecrets != redact) {
            this.redactSecrets = redact;
            fireTableDataChanged();
        }
    }

    public boolean isRedactSecrets() {
        return redactSecrets;
    }

    public void setShowSuppressed(boolean show) {
        if (this.showSuppressed != show) {
            this.showSuppressed = show;
            applyFilters();
        }
    }

    public boolean isShowSuppressed() {
        return showSuppressed;
    }

    public void setTextFilter(String filter) {
        this.textFilter = filter == null ? "" : filter.trim().toLowerCase(Locale.ROOT);
        applyFilters();
    }

    public void setCategoryFilter(FindingCategory cat) {
        this.categoryFilter = cat;
        applyFilters();
    }

    public void setSeverityFilter(FindingSeverity sev) {
        this.severityFilter = sev;
        applyFilters();
    }

    public void applyFilters() {
        filteredFindings.clear();
        for (UnifiedFinding f : allFindings) {
            if (!showSuppressed && f.suppressed()) {
                continue;
            }
            if (categoryFilter != null && f.category() != categoryFilter) {
                continue;
            }
            if (severityFilter != null && f.severity() != severityFilter) {
                continue;
            }
            if (!textFilter.isEmpty()) {
                String hexAddr = "0x" + Long.toHexString(f.address()).toLowerCase(Locale.ROOT);
                boolean matches = f.target().toLowerCase(Locale.ROOT).contains(textFilter)
                        || f.explanation().toLowerCase(Locale.ROOT).contains(textFilter)
                        || f.id().toLowerCase(Locale.ROOT).contains(textFilter)
                        || hexAddr.contains(textFilter)
                        || f.subcategory().toLowerCase(Locale.ROOT).contains(textFilter);
                if (!matches) {
                    continue;
                }
            }
            filteredFindings.add(f);
        }
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return filteredFindings.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        UnifiedFinding f = getFindingAt(rowIndex);
        if (f == null) {
            return "";
        }
        return switch (columnIndex) {
            case COL_SEVERITY -> f.severity().displayName();
            case COL_CONFIDENCE -> f.confidence().displayName();
            case COL_CATEGORY -> f.category().displayName() + " (" + f.subcategory() + ")";
            case COL_ADDRESS -> "0x" + Long.toHexString(f.address()).toUpperCase(Locale.ROOT);
            case COL_TARGET -> f.maskedTarget(redactSecrets);
            case COL_PLATFORM -> f.platform();
            case COL_STATUS -> f.suppressed() ? "Suppressed" : "Active";
            case COL_EXPLANATION -> f.explanation();
            default -> "";
        };
    }
}
