package io.github.rezabakhshi.embedra.ghidra.diff;

import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import io.github.rezabakhshi.embedra.analyzers.diff.DiffChangeKind;
import io.github.rezabakhshi.embedra.analyzers.diff.FirmwareWorkspaceDiff;
import io.github.rezabakhshi.embedra.analyzers.diff.FirmwareWorkspaceDiffEngine;
import io.github.rezabakhshi.embedra.analyzers.diff.FunctionDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.MemoryDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.MetadataDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.PartitionDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.StringDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.SymbolDiffEntry;
import io.github.rezabakhshi.embedra.analyzers.diff.WorkspaceSnapshot;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Component provider for the Embedra firmware workspace differential comparison.
 * Offers multi-view inspection (Functions, Symbols, Strings, Metadata, Memory, Partitions),
 * filtering, secret redaction, double-click address navigation, and JSON/Markdown/SARIF export.
 */
public final class EmbedraDiffProvider extends ComponentProviderAdapter {

    private final JPanel mainPanel;

    private final JTabbedPane tabbedPane;

    private final JLabel statusLabel;

    private final DiffTableModels.FunctionTableModel functionModel;

    private final DiffTableModels.SymbolTableModel symbolModel;

    private final DiffTableModels.StringTableModel stringModel;

    private final DiffTableModels.MetadataTableModel metadataModel;

    private final DiffTableModels.MemoryTableModel memoryModel;

    private final DiffTableModels.PartitionTableModel partitionModel;

    private final JTable functionTable;

    private final JTable symbolTable;

    private final JTable stringTable;

    private final JTable metadataTable;

    private final JTable memoryTable;

    private final JTable partitionTable;

    private final JComboBox<ProgramItem> sourceProgramBox;

    private final JComboBox<ProgramItem> targetProgramBox;

    private final JCheckBox redactSecretsBox;

    private final JComboBox<String> kindFilterBox;

    private final JTextField textFilterField;

    private Program sourceProgram;

    private Program targetProgram;

    private FirmwareWorkspaceDiff currentDiff;

    private final GhidraWorkspaceDiffExtractor extractor = new GhidraWorkspaceDiffExtractor();

    private final FirmwareWorkspaceDiffEngine diffEngine = new FirmwareWorkspaceDiffEngine();

    public EmbedraDiffProvider(PluginTool tool, String owner) {
        super(tool, "Embedra Workspace Diff", owner);

        this.functionModel = new DiffTableModels.FunctionTableModel();
        this.symbolModel = new DiffTableModels.SymbolTableModel();
        this.stringModel = new DiffTableModels.StringTableModel();
        this.metadataModel = new DiffTableModels.MetadataTableModel();
        this.memoryModel = new DiffTableModels.MemoryTableModel();
        this.partitionModel = new DiffTableModels.PartitionTableModel();

        this.functionTable = createTable(functionModel);
        this.symbolTable = createTable(symbolModel);
        this.stringTable = createTable(stringModel);
        this.metadataTable = createTable(metadataModel);
        this.memoryTable = createTable(memoryModel);
        this.partitionTable = createTable(partitionModel);

        this.tabbedPane = new JTabbedPane();
        this.statusLabel = new JLabel("No diff calculated. Select source and target programs and click Compare.");
        this.sourceProgramBox = new JComboBox<>();
        this.targetProgramBox = new JComboBox<>();
        this.redactSecretsBox = new JCheckBox("Redact Secrets", true);
        this.kindFilterBox = new JComboBox<>(new String[]{
                "All Changes", "ADDED", "REMOVED", "MODIFIED", "MOVED", "UNCHANGED"
        });
        this.textFilterField = new JTextField(12);

        this.mainPanel = new JPanel(new BorderLayout());

        setupUI();
        setupNavigation();
        setTitle("Embedra Workspace Diff");
    }

    private JTable createTable(javax.swing.table.TableModel model) {
        JTable table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        return table;
    }

    private void setupUI() {
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));

        // Program selection bar
        JPanel progPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        progPanel.add(new JLabel("Source:"));
        sourceProgramBox.setPreferredSize(new Dimension(180, 24));
        progPanel.add(sourceProgramBox);

        progPanel.add(new JLabel("Target:"));
        targetProgramBox.setPreferredSize(new Dimension(180, 24));
        progPanel.add(targetProgramBox);

        JButton compareBtn = new JButton("Compare");
        compareBtn.addActionListener(e -> runComparison());
        progPanel.add(compareBtn);

        topContainer.add(progPanel);

        // Filter and Options bar
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        filterPanel.add(new JLabel("Filter:"));
        filterPanel.add(textFilterField);

        filterPanel.add(new JLabel("Type:"));
        filterPanel.add(kindFilterBox);

        filterPanel.add(redactSecretsBox);

        redactSecretsBox.addActionListener(e -> {
            boolean redact = redactSecretsBox.isSelected();
            stringModel.setRedactSecrets(redact);
            metadataModel.setRedactSecrets(redact);
        });

        kindFilterBox.addActionListener(e -> applyFilters());

        textFilterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applyFilters();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyFilters();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applyFilters();
            }
        });

        // Export buttons
        JButton jsonExportBtn = new JButton("Export JSON");
        jsonExportBtn.addActionListener(e -> exportDiff("json"));
        filterPanel.add(jsonExportBtn);

        JButton mdExportBtn = new JButton("Export Markdown");
        mdExportBtn.addActionListener(e -> exportDiff("md"));
        filterPanel.add(mdExportBtn);

        JButton sarifExportBtn = new JButton("Export SARIF");
        sarifExportBtn.addActionListener(e -> exportDiff("sarif"));
        filterPanel.add(sarifExportBtn);

        topContainer.add(filterPanel);

        mainPanel.add(topContainer, BorderLayout.NORTH);

        // Tabbed views
        tabbedPane.addTab("Functions (0)", new JScrollPane(functionTable));
        tabbedPane.addTab("Symbols (0)", new JScrollPane(symbolTable));
        tabbedPane.addTab("Strings (0)", new JScrollPane(stringTable));
        tabbedPane.addTab("Metadata (0)", new JScrollPane(metadataTable));
        tabbedPane.addTab("Memory (0)", new JScrollPane(memoryTable));
        tabbedPane.addTab("Partitions (0)", new JScrollPane(partitionTable));

        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        // Status bar
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        statusPanel.setBorder(BorderFactory.createEtchedBorder());
        statusPanel.add(statusLabel);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);
    }

    private void setupNavigation() {
        functionTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = functionTable.getSelectedRow();
                    if (row >= 0) {
                        int modelRow = functionTable.convertRowIndexToModel(row);
                        FunctionDiffEntry entry = functionModel.getEntryAt(modelRow);
                        if (entry != null) {
                            Long addr = entry.targetAddress() != null ? entry.targetAddress() : entry.sourceAddress();
                            navigateToAddress(addr);
                        }
                    }
                }
            }
        });

        symbolTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = symbolTable.getSelectedRow();
                    if (row >= 0) {
                        int modelRow = symbolTable.convertRowIndexToModel(row);
                        SymbolDiffEntry entry = symbolModel.getEntryAt(modelRow);
                        if (entry != null) {
                            Long addr = entry.targetAddress() != null ? entry.targetAddress() : entry.sourceAddress();
                            navigateToAddress(addr);
                        }
                    }
                }
            }
        });

        stringTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = stringTable.getSelectedRow();
                    if (row >= 0) {
                        int modelRow = stringTable.convertRowIndexToModel(row);
                        StringDiffEntry entry = stringModel.getEntryAt(modelRow);
                        if (entry != null) {
                            Long addr = entry.targetAddress() != null ? entry.targetAddress() : entry.sourceAddress();
                            navigateToAddress(addr);
                        }
                    }
                }
            }
        });

        memoryTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = memoryTable.getSelectedRow();
                    if (row >= 0) {
                        int modelRow = memoryTable.convertRowIndexToModel(row);
                        MemoryDiffEntry entry = memoryModel.getEntryAt(modelRow);
                        if (entry != null) {
                            Long addr = entry.targetAddress() != null ? entry.targetAddress() : entry.sourceAddress();
                            navigateToAddress(addr);
                        }
                    }
                }
            }
        });
    }

    private void navigateToAddress(Long offset) {
        if (offset == null || getTool() == null) {
            return;
        }
        GoToService goToService = getTool().getService(GoToService.class);
        if (goToService == null) {
            return;
        }
        Program target = targetProgram != null ? targetProgram : sourceProgram;
        if (target == null) {
            return;
        }
        Address addr = target.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        if (addr != null) {
            goToService.goTo(addr);
        }
    }

    public void updateOpenPrograms(Program[] programs, Program activeProgram) {
        ProgramItem currentSource = (ProgramItem) sourceProgramBox.getSelectedItem();
        ProgramItem currentTarget = (ProgramItem) targetProgramBox.getSelectedItem();

        sourceProgramBox.removeAllItems();
        targetProgramBox.removeAllItems();

        if (programs != null) {
            for (Program p : programs) {
                ProgramItem item = new ProgramItem(p);
                sourceProgramBox.addItem(item);
                targetProgramBox.addItem(item);
            }
        }

        if (currentSource != null) {
            selectProgram(sourceProgramBox, currentSource.program);
        } else if (programs != null && programs.length > 0) {
            sourceProgramBox.setSelectedIndex(0);
        }

        if (currentTarget != null) {
            selectProgram(targetProgramBox, currentTarget.program);
        } else if (programs != null && programs.length > 1) {
            targetProgramBox.setSelectedIndex(1);
        } else if (programs != null && programs.length > 0) {
            targetProgramBox.setSelectedIndex(0);
        }

        if (activeProgram != null && (currentTarget == null || currentTarget.program == null)) {
            selectProgram(targetProgramBox, activeProgram);
        }
    }

    private void selectProgram(JComboBox<ProgramItem> box, Program p) {
        for (int i = 0; i < box.getItemCount(); i++) {
            if (box.getItemAt(i).program.equals(p)) {
                box.setSelectedIndex(i);
                return;
            }
        }
    }

    public void setPrograms(Program source, Program target) {
        this.sourceProgram = source;
        this.targetProgram = target;
        Program[] list;
        if (source != null && target != null) {
            list = new Program[]{source, target};
        } else if (source != null) {
            list = new Program[]{source};
        } else if (target != null) {
            list = new Program[]{target};
        } else {
            list = new Program[0];
        }
        updateOpenPrograms(list, target);
    }

    public void runComparison() {
        ProgramItem srcItem = (ProgramItem) sourceProgramBox.getSelectedItem();
        ProgramItem tgtItem = (ProgramItem) targetProgramBox.getSelectedItem();

        Program srcProg = srcItem != null ? srcItem.program : sourceProgram;
        Program tgtProg = tgtItem != null ? tgtItem.program : targetProgram;

        if (srcProg == null || tgtProg == null) {
            JOptionPane.showMessageDialog(mainPanel, "Select source and target programs.",
                    "Embedra Diff", JOptionPane.WARNING_MESSAGE);
            return;
        }

        this.sourceProgram = srcProg;
        this.targetProgram = tgtProg;

        try {
            WorkspaceSnapshot srcSnapshot = extractor.extract(srcProg);
            WorkspaceSnapshot tgtSnapshot = extractor.extract(tgtProg);

            this.currentDiff = diffEngine.compare(srcSnapshot, tgtSnapshot);

            functionModel.setEntries(currentDiff.functions());
            symbolModel.setEntries(currentDiff.symbols());
            stringModel.setEntries(currentDiff.strings());
            metadataModel.setEntries(currentDiff.metadata());
            memoryModel.setEntries(currentDiff.memoryBlocks());
            partitionModel.setEntries(currentDiff.partitions());

            tabbedPane.setTitleAt(0, "Functions (" + currentDiff.functions().size() + ")");
            tabbedPane.setTitleAt(1, "Symbols (" + currentDiff.symbols().size() + ")");
            tabbedPane.setTitleAt(2, "Strings (" + currentDiff.strings().size() + ")");
            tabbedPane.setTitleAt(3, "Metadata (" + currentDiff.metadata().size() + ")");
            tabbedPane.setTitleAt(4, "Memory (" + currentDiff.memoryBlocks().size() + ")");
            tabbedPane.setTitleAt(5, "Partitions (" + currentDiff.partitions().size() + ")");

            String status = String.format(
                    "Comparison: %s vs %s | Diffs: %d | F:%d S:%d Str:%d M:%d Mem:%d P:%d",
                    srcProg.getName(), tgtProg.getName(),
                    currentDiff.totalDifferences(),
                    currentDiff.functionDifferenceCount(),
                    currentDiff.symbolDifferenceCount(),
                    currentDiff.stringDifferenceCount(),
                    currentDiff.metadataDifferenceCount(),
                    currentDiff.memoryDifferenceCount(),
                    currentDiff.partitionDifferenceCount());
            statusLabel.setText(status);
        } catch (DiagnosticException ex) {
            JOptionPane.showMessageDialog(mainPanel, "Comparison failed: " + ex.getMessage(),
                    "Embedra Diff Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void applyFilters() {
        String filterText = textFilterField.getText();
        String selectedKind = (String) kindFilterBox.getSelectedItem();
        DiffChangeKind kind = null;
        if (selectedKind != null && !selectedKind.equals("All Changes")) {
            kind = DiffChangeKind.valueOf(selectedKind);
        }

        functionModel.setFilters(kind, filterText);
        symbolModel.setFilters(kind, filterText);
        stringModel.setFilters(kind, filterText);
        metadataModel.setFilters(kind, filterText);
        memoryModel.setFilters(kind, filterText);
        partitionModel.setFilters(kind, filterText);
    }

    private void exportDiff(String format) {
        if (currentDiff == null) {
            JOptionPane.showMessageDialog(mainPanel, "No diff results available to export.",
                    "Export Diff", JOptionPane.WARNING_MESSAGE);
            return;
        }

        boolean redactSecrets = redactSecretsBox.isSelected();
        String content = switch (format.toLowerCase()) {
            case "json" -> currentDiff.toJson(redactSecrets);
            case "md", "markdown" -> currentDiff.toMarkdown(redactSecrets);
            case "sarif" -> currentDiff.toSarif(redactSecrets);
            default -> "";
        };

        JFileChooser chooser = new JFileChooser();
        String ext = format.equals("markdown") ? "md" : format;
        String fileName = String.format("embedra-diff-%s-vs-%s.%s",
                currentDiff.sourceWorkspace(), currentDiff.targetWorkspace(), ext);
        chooser.setSelectedFile(new File(fileName));

        int ret = chooser.showSaveDialog(mainPanel);
        if (ret == JFileChooser.APPROVE_OPTION) {
            File dest = chooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(dest, StandardCharsets.UTF_8)) {
                writer.write(content);
                JOptionPane.showMessageDialog(mainPanel, "Diff exported to " + dest.getAbsolutePath(),
                        "Export Diff", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(mainPanel, "Failed to write file: " + ex.getMessage(),
                        "Export Diff Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public FirmwareWorkspaceDiff getCurrentDiff() {
        return currentDiff;
    }

    public DiffTableModels.FunctionTableModel getFunctionTableModel() {
        return functionModel;
    }

    public DiffTableModels.SymbolTableModel getSymbolTableModel() {
        return symbolModel;
    }

    public DiffTableModels.StringTableModel getStringTableModel() {
        return stringModel;
    }

    public DiffTableModels.MetadataTableModel getMetadataTableModel() {
        return metadataModel;
    }

    public DiffTableModels.MemoryTableModel getMemoryTableModel() {
        return memoryModel;
    }

    public DiffTableModels.PartitionTableModel getPartitionTableModel() {
        return partitionModel;
    }

    public JTabbedPane getTabbedPane() {
        return tabbedPane;
    }

    public void dispose() {
        removeFromTool();
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    private static class ProgramItem {

        final Program program;

        ProgramItem(Program p) {
            this.program = p;
        }

        @Override
        public String toString() {
            return program != null ? program.getName() : "<none>";
        }
    }
}
