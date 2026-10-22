package com.autorize.ui;

import com.autorize.model.EnforcementDetector;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

public class DetectorConfigPanel extends JPanel {

    private final List<EnforcementDetector> detectors;
    private final Runnable onCommit;
    private final Consumer<Boolean> onLogicChanged;
    private final Runnable onResetDefaults;

    private final DetectorTableModel tableModel;
    private final JTable table;

    private final JComboBox<EnforcementDetector.DetectorType> typeBox;
    private final JTextArea contentArea;
    private final JCheckBox enabledCheckBox;
    private final JComboBox<String> logicBox;
    private final JButton updateBtn;

    public DetectorConfigPanel(String panelTitle,
                               List<EnforcementDetector> detectors,
                               boolean isAndLogic,
                               Consumer<Boolean> onLogicChanged,
                               Runnable onCommit,
                               Runnable onResetDefaults) {
        super(new BorderLayout(8, 8));
        this.detectors = detectors;
        this.onCommit = onCommit;
        this.onLogicChanged = onLogicChanged;
        this.onResetDefaults = onResetDefaults;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // 1. Table & Model Setup
        tableModel = new DetectorTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);

        // Column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(65);
        table.getColumnModel().getColumn(0).setMaxWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(220);
        table.getColumnModel().getColumn(2).setPreferredWidth(450);

        // Center align Enabled checkbox header
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);

        // 2. Form & Controls Panel
        JPanel formPanel = new JPanel(new BorderLayout(6, 6));
        formPanel.setBorder(new TitledBorder(panelTitle));

        JPanel inputsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Type + Enabled
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        inputsPanel.add(new JLabel("Detector Type:"), gbc);

        typeBox = new JComboBox<>(EnforcementDetector.DetectorType.values());
        typeBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof EnforcementDetector.DetectorType dt) {
                    setText(dt.getLabel());
                }
                return this;
            }
        });
        gbc.gridx = 1; gbc.weightx = 1.0;
        inputsPanel.add(typeBox, gbc);

        enabledCheckBox = new JCheckBox("Enabled", true);
        gbc.gridx = 2; gbc.weightx = 0;
        inputsPanel.add(enabledCheckBox, gbc);

        // Row 1: Content / Pattern
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        inputsPanel.add(new JLabel("Value / Pattern:"), gbc);

        contentArea = new JTextArea(3, 30);
        contentArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        contentArea.setLineWrap(true);
        contentArea.setWrapStyleWord(true);
        JScrollPane contentScroll = new JScrollPane(contentArea);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        inputsPanel.add(contentScroll, gbc);

        // Row 2: Logic & Action Buttons
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        buttonRow.add(new JLabel("Match Logic:"));
        logicBox = new JComboBox<>(new String[]{
                "OR (Any detector match triggers enforcement)",
                "AND (All configured detectors must match)"
        });
        logicBox.setSelectedIndex(isAndLogic ? 1 : 0);
        logicBox.addActionListener(e -> {
            if (this.onLogicChanged != null) {
                this.onLogicChanged.accept(logicBox.getSelectedIndex() == 1);
            }
            commit();
        });
        buttonRow.add(logicBox);

        JButton addBtn = new JButton("Add Fingerprint");
        updateBtn = new JButton("Update Selected");
        updateBtn.setEnabled(false);
        JButton delBtn = new JButton("Remove Selected");
        JButton resetBtn = new JButton("Reset Defaults");

        addBtn.addActionListener(e -> addDetector());
        updateBtn.addActionListener(e -> updateSelectedDetector());
        delBtn.addActionListener(e -> removeSelectedDetector());
        resetBtn.addActionListener(e -> resetDefaults());

        buttonRow.add(addBtn);
        buttonRow.add(updateBtn);
        buttonRow.add(delBtn);
        buttonRow.add(resetBtn);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3; gbc.fill = GridBagConstraints.HORIZONTAL;
        inputsPanel.add(buttonRow, gbc);

        formPanel.add(inputsPanel, BorderLayout.CENTER);

        // 3. Selection Listener on Table
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selected = table.getSelectedRow();
                if (selected >= 0) {
                    int modelIndex = table.convertRowIndexToModel(selected);
                    EnforcementDetector det = detectors.get(modelIndex);
                    typeBox.setSelectedItem(det.getType());
                    contentArea.setText(det.getContent() != null ? det.getContent() : "");
                    enabledCheckBox.setSelected(det.isEnabled());
                    updateBtn.setEnabled(true);
                } else {
                    updateBtn.setEnabled(false);
                }
            }
        });

        add(formPanel, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    private void addDetector() {
        EnforcementDetector.DetectorType type = (EnforcementDetector.DetectorType) typeBox.getSelectedItem();
        String content = contentArea.getText().trim();
        boolean enabled = enabledCheckBox.isSelected();

        if (content.isEmpty() && type != EnforcementDetector.DetectorType.GRAPHQL_ERROR_PRESENT) {
            JOptionPane.showMessageDialog(this, "Please enter a value, status code, or regex pattern for this detector.",
                    "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        EnforcementDetector detector = new EnforcementDetector(type, content);
        detector.setEnabled(enabled);
        detectors.add(detector);
        tableModel.fireTableRowsInserted(detectors.size() - 1, detectors.size() - 1);
        commit();
        contentArea.setText("");
    }

    private void updateSelectedDetector() {
        int selected = table.getSelectedRow();
        if (selected >= 0) {
            int modelIndex = table.convertRowIndexToModel(selected);
            EnforcementDetector det = detectors.get(modelIndex);
            det.setType((EnforcementDetector.DetectorType) typeBox.getSelectedItem());
            det.setContent(contentArea.getText().trim());
            det.setEnabled(enabledCheckBox.isSelected());
            tableModel.fireTableRowsUpdated(modelIndex, modelIndex);
            commit();
        }
    }

    private void removeSelectedDetector() {
        int selected = table.getSelectedRow();
        if (selected >= 0) {
            int modelIndex = table.convertRowIndexToModel(selected);
            detectors.remove(modelIndex);
            tableModel.fireTableRowsDeleted(modelIndex, modelIndex);
            commit();
            contentArea.setText("");
            updateBtn.setEnabled(false);
        }
    }

    private void resetDefaults() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Reset detector fingerprints to recommended defaults?",
                "Reset Defaults", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION && onResetDefaults != null) {
            onResetDefaults.run();
            tableModel.fireTableDataChanged();
            commit();
        }
    }

    private void commit() {
        if (onCommit != null) {
            onCommit.run();
        }
    }

    private class DetectorTableModel extends AbstractTableModel {
        private final String[] columns = {"Enabled", "Detector Type", "Value / Regex Pattern"};

        @Override
        public int getRowCount() {
            return detectors.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Boolean.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0; // Checkbox is editable directly
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= detectors.size()) return null;
            EnforcementDetector det = detectors.get(rowIndex);
            switch (columnIndex) {
                case 0: return det.isEnabled();
                case 1: return det.getType() != null ? det.getType().getLabel() : "";
                case 2: return det.getContent();
                default: return "";
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && rowIndex >= 0 && rowIndex < detectors.size()) {
                detectors.get(rowIndex).setEnabled((Boolean) aValue);
                commit();
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
