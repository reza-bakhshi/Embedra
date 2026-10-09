package io.github.rezabakhshi.embedra.ghidra.findings;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingCategory;
import io.github.rezabakhshi.embedra.analyzers.findings.FindingSeverity;
import io.github.rezabakhshi.embedra.analyzers.findings.SuppressionEngine;
import io.github.rezabakhshi.embedra.analyzers.findings.SuppressionRule;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFinding;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFindingsReport;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Sortable, filterable findings panel provider for the Ghidra CodeBrowser (AN-006, AN-008).
 */
public final class EmbedraFindingsProvider extends ComponentProviderAdapter {

    private final JPanel mainPanel;

    private final FindingsTableModel tableModel;

    private final JTable table;

    private final JLabel statusLabel;

    private final SuppressionEngine suppressionEngine;

    private Program currentProgram;

    public EmbedraFindingsProvider(PluginTool tool, String owner) {
        super(tool, "Embedra Findings", owner);
        this.suppressionEngine = new SuppressionEngine();
        this.tableModel = new FindingsTableModel();
        this.table = new JTable(tableModel);
        this.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.table.setAutoCreateRowSorter(true);

        this.mainPanel = new JPanel(new BorderLayout());
        this.statusLabel = new JLabel("Findings: 0 active, 0 suppressed");

        setupUI();
        setTitle("Embedra Findings");
    }

    private void setupUI() {
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));

        // Text filter
        filterPanel.add(new JLabel("Filter:"));
        JTextField filterField = new JTextField(12);
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                tableModel.setTextFilter(filterField.getText());
                updateStatus();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                tableModel.setTextFilter(filterField.getText());
                updateStatus();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                tableModel.setTextFilter(filterField.getText());
                updateStatus();
            }
        });
        filterPanel.add(filterField);

        // Category filter
        filterPanel.add(new JLabel("Category:"));
        JComboBox<String> catBox = new JComboBox<>();
        catBox.addItem("All Categories");
        for (FindingCategory cat : FindingCategory.values()) {
            catBox.addItem(cat.name());
        }
        catBox.addActionListener(e -> {
            String sel = (String) catBox.getSelectedItem();
            if (sel == null || sel.equals("All Categories")) {
                tableModel.setCategoryFilter(null);
            } else {
                tableModel.setCategoryFilter(FindingCategory.valueOf(sel));
            }
            updateStatus();
        });
        filterPanel.add(catBox);

        // Severity filter
        filterPanel.add(new JLabel("Severity:"));
        JComboBox<String> sevBox = new JComboBox<>();
        sevBox.addItem("All Severities");
        for (FindingSeverity sev : FindingSeverity.values()) {
            sevBox.addItem(sev.name());
        }
        sevBox.addActionListener(e -> {
            String sel = (String) sevBox.getSelectedItem();
            if (sel == null || sel.equals("All Severities")) {
                tableModel.setSeverityFilter(null);
            } else {
                tableModel.setSeverityFilter(FindingSeverity.valueOf(sel));
            }
            updateStatus();
        });
        filterPanel.add(sevBox);

        // Show Suppressed checkbox
        JCheckBox showSuppressedBox = new JCheckBox("Show Suppressed", true);
        showSuppressedBox.addActionListener(e -> {
            tableModel.setShowSuppressed(showSuppressedBox.isSelected());
            updateStatus();
        });
        filterPanel.add(showSuppressedBox);

        // Redact Secrets checkbox (default true)
        JCheckBox redactSecretsBox = new JCheckBox("Redact Secrets", true);
        redactSecretsBox.addActionListener(e -> tableModel.setRedactSecrets(redactSecretsBox.isSelected()));
        filterPanel.add(redactSecretsBox);

        // Suppress Button
        JButton suppressBtn = new JButton("Suppress");
        suppressBtn.addActionListener(e -> handleSuppress());
        filterPanel.add(suppressBtn);

        // Unsuppress Button
        JButton unsuppressBtn = new JButton("Unsuppress");
        unsuppressBtn.addActionListener(e -> handleUnsuppress());
        filterPanel.add(unsuppressBtn);

        // Double-click navigation
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    navigateToSelectedFinding();
                }
            }
        });

        mainPanel.add(filterPanel, BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottomPanel.add(statusLabel);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);
    }

    public void setProgram(Program program) {
        this.currentProgram = program;
        refreshFindings();
    }

    public void setFindings(List<UnifiedFinding> findings) {
        Objects.requireNonNull(findings, "findings must not be null");
        List<UnifiedFinding> evaluated = suppressionEngine.applySuppression(findings);
        tableModel.setFindings(evaluated);
        updateStatus();
    }

    public void refreshFindings() {
        if (currentProgram == null) {
            tableModel.setFindings(List.of());
            updateStatus();
            return;
        }

        List<UnifiedFinding> discovered = GhidraFindingBookmarkSynchronizer
                .extractFindingsFromBookmarks(currentProgram);
        List<UnifiedFinding> evaluated = suppressionEngine.applySuppression(discovered);
        tableModel.setFindings(evaluated);
        updateStatus();
    }

    private void handleSuppress() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        int modelRow = table.convertRowIndexToModel(selectedRow);
        UnifiedFinding finding = tableModel.getFindingAt(modelRow);
        if (finding == null) {
            return;
        }

        String reason = JOptionPane.showInputDialog(
                mainPanel,
                "Enter suppression reason for " + finding.id() + ":",
                "Suppress Finding",
                JOptionPane.PLAIN_MESSAGE);

        if (reason == null) {
            return;
        }

        SuppressionRule rule = SuppressionRule.of(
                "RULE-" + finding.id(),
                SuppressionRule.MatchType.FINDING_ID,
                finding.id(),
                reason.isBlank() ? "User suppressed" : reason);

        suppressionEngine.addRule(rule);
        if (currentProgram != null) {
            GhidraFindingBookmarkSynchronizer.setFindingSuppression(currentProgram, finding, true, reason);
        }

        refreshFindings();
    }

    private void handleUnsuppress() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        int modelRow = table.convertRowIndexToModel(selectedRow);
        UnifiedFinding finding = tableModel.getFindingAt(modelRow);
        if (finding == null) {
            return;
        }

        suppressionEngine.removeRule("RULE-" + finding.id());
        if (currentProgram != null) {
            GhidraFindingBookmarkSynchronizer.setFindingSuppression(currentProgram, finding, false, null);
        }

        refreshFindings();
    }

    private void navigateToSelectedFinding() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow < 0 || currentProgram == null) {
            return;
        }
        int modelRow = table.convertRowIndexToModel(selectedRow);
        UnifiedFinding finding = tableModel.getFindingAt(modelRow);
        if (finding == null) {
            return;
        }

        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(finding.address());
        if (addr != null && getTool() != null) {
            GoToService goToService = getTool().getService(GoToService.class);
            if (goToService != null) {
                goToService.goTo(addr);
            }
        }
    }

    private void updateStatus() {
        int total = tableModel.getRowCount();
        int active = 0;
        int suppressed = 0;
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            UnifiedFinding f = tableModel.getFindingAt(i);
            if (f != null) {
                if (f.suppressed()) {
                    suppressed++;
                } else {
                    active++;
                }
            }
        }
        statusLabel.setText(String.format("Showing: %d findings (%d active, %d suppressed)",
                total, active, suppressed));
    }

    public FindingsTableModel getTableModel() {
        return tableModel;
    }

    public SuppressionEngine getSuppressionEngine() {
        return suppressionEngine;
    }

    public void dispose() {
        removeFromTool();
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}
