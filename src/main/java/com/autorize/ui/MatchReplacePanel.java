package com.autorize.ui;

import com.autorize.model.MatchReplaceRule;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;

public class MatchReplacePanel extends JPanel {

    private final List<MatchReplaceRule> rules;
    private final Runnable onCommit;

    private final MatchReplaceTableModel tableModel;
    private final JTable table;

    private final JComboBox<MatchReplaceRule.RuleType> typeBox;
    private final JTextField matchField;
    private final JTextField replaceField;
    private final JCheckBox enabledCheckBox;
    private final JButton updateBtn;

    public MatchReplacePanel(List<MatchReplaceRule> rules, Runnable onCommit) {
        super(new BorderLayout(8, 8));
        this.rules = rules;
        this.onCommit = onCommit;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        tableModel = new MatchReplaceTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);

        table.getColumnModel().getColumn(0).setPreferredWidth(65);
        table.getColumnModel().getColumn(0).setMaxWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(180);
        table.getColumnModel().getColumn(2).setPreferredWidth(260);
        table.getColumnModel().getColumn(3).setPreferredWidth(260);

        JPanel formPanel = new JPanel(new BorderLayout(6, 6));
        formPanel.setBorder(new TitledBorder("Match & Replace Rule Configuration"));

        JPanel inputsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Type + Enabled
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        inputsPanel.add(new JLabel("Rule Type:"), gbc);

        typeBox = new JComboBox<>(MatchReplaceRule.RuleType.values());
        typeBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof MatchReplaceRule.RuleType rt) {
                    setText(rt.getLabel());
                }
                return this;
            }
        });
        gbc.gridx = 1; gbc.weightx = 1.0;
        inputsPanel.add(typeBox, gbc);

        enabledCheckBox = new JCheckBox("Enabled", true);
        gbc.gridx = 2; gbc.weightx = 0;
        inputsPanel.add(enabledCheckBox, gbc);

        // Row 1: Match String / Regex
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        inputsPanel.add(new JLabel("Match:"), gbc);

        matchField = new JTextField(24);
        matchField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        inputsPanel.add(matchField, gbc);

        // Row 2: Replace String
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1; gbc.weightx = 0;
        inputsPanel.add(new JLabel("Replace:"), gbc);

        replaceField = new JTextField(24);
        replaceField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        inputsPanel.add(replaceField, gbc);

        // Row 3: Buttons
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JButton addBtn = new JButton("Add Rule");
        updateBtn = new JButton("Update Selected");
        updateBtn.setEnabled(false);
        JButton delBtn = new JButton("Remove Selected");

        addBtn.addActionListener(e -> addRule());
        updateBtn.addActionListener(e -> updateSelectedRule());
        delBtn.addActionListener(e -> removeSelectedRule());

        buttonRow.add(addBtn);
        buttonRow.add(updateBtn);
        buttonRow.add(delBtn);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        inputsPanel.add(buttonRow, gbc);

        formPanel.add(inputsPanel, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selected = table.getSelectedRow();
                if (selected >= 0) {
                    int modelIndex = table.convertRowIndexToModel(selected);
                    MatchReplaceRule rule = rules.get(modelIndex);
                    typeBox.setSelectedItem(rule.getType());
                    matchField.setText(rule.getMatch() != null ? rule.getMatch() : "");
                    replaceField.setText(rule.getReplace() != null ? rule.getReplace() : "");
                    enabledCheckBox.setSelected(rule.isEnabled());
                    updateBtn.setEnabled(true);
                } else {
                    updateBtn.setEnabled(false);
                }
            }
        });

        add(formPanel, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    private void addRule() {
        MatchReplaceRule.RuleType type = (MatchReplaceRule.RuleType) typeBox.getSelectedItem();
        String match = matchField.getText();
        String replace = replaceField.getText();
        boolean enabled = enabledCheckBox.isSelected();

        if (match == null || match.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Match string/pattern cannot be empty.",
                    "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        MatchReplaceRule rule = new MatchReplaceRule(type, match, replace);
        rule.setEnabled(enabled);
        rules.add(rule);
        tableModel.fireTableRowsInserted(rules.size() - 1, rules.size() - 1);
        commit();
        matchField.setText("");
        replaceField.setText("");
    }

    private void updateSelectedRule() {
        int selected = table.getSelectedRow();
        if (selected >= 0) {
            int modelIndex = table.convertRowIndexToModel(selected);
            MatchReplaceRule rule = rules.get(modelIndex);
            rule.setType((MatchReplaceRule.RuleType) typeBox.getSelectedItem());
            rule.setMatch(matchField.getText());
            rule.setReplace(replaceField.getText());
            rule.setEnabled(enabledCheckBox.isSelected());
            tableModel.fireTableRowsUpdated(modelIndex, modelIndex);
            commit();
        }
    }

    private void removeSelectedRule() {
        int selected = table.getSelectedRow();
        if (selected >= 0) {
            int modelIndex = table.convertRowIndexToModel(selected);
            rules.remove(modelIndex);
            tableModel.fireTableRowsDeleted(modelIndex, modelIndex);
            commit();
            matchField.setText("");
            replaceField.setText("");
            updateBtn.setEnabled(false);
        }
    }

    private void commit() {
        if (onCommit != null) {
            onCommit.run();
        }
    }

    private class MatchReplaceTableModel extends AbstractTableModel {
        private final String[] columns = {"Enabled", "Type", "Match", "Replace"};

        @Override
        public int getRowCount() {
            return rules.size();
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
            return columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= rules.size()) return null;
            MatchReplaceRule r = rules.get(rowIndex);
            switch (columnIndex) {
                case 0: return r.isEnabled();
                case 1: return r.getType() != null ? r.getType().getLabel() : "";
                case 2: return r.getMatch();
                case 3: return r.getReplace();
                default: return "";
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && rowIndex >= 0 && rowIndex < rules.size()) {
                rules.get(rowIndex).setEnabled((Boolean) aValue);
                commit();
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
