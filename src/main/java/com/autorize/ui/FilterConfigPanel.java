package com.autorize.ui;

import com.autorize.model.InterceptionFilter;
import com.autorize.persistence.PersistenceManager;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;

public class FilterConfigPanel extends JPanel {

    private final PersistenceManager persistenceManager;
    private final FilterTableModel tableModel;
    private final JTable table;

    private final JComboBox<InterceptionFilter.FilterType> typeBox;
    private final JTextField contentField;
    private final JCheckBox enabledCheckBox;
    private final JButton updateBtn;

    public FilterConfigPanel(PersistenceManager persistenceManager) {
        super(new BorderLayout(8, 8));
        this.persistenceManager = persistenceManager;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        tableModel = new FilterTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);

        table.getColumnModel().getColumn(0).setPreferredWidth(65);
        table.getColumnModel().getColumn(0).setMaxWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(220);
        table.getColumnModel().getColumn(2).setPreferredWidth(450);

        JPanel formPanel = new JPanel(new BorderLayout(6, 6));
        formPanel.setBorder(new TitledBorder("Interception Filter Configuration"));

        JPanel inputsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Type + Enabled
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        inputsPanel.add(new JLabel("Filter Type:"), gbc);

        typeBox = new JComboBox<>(InterceptionFilter.FilterType.values());
        typeBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof InterceptionFilter.FilterType ft) {
                    setText(ft.getLabel());
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
        inputsPanel.add(new JLabel("Pattern / Value:"), gbc);

        contentField = new JTextField(25);
        contentField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        inputsPanel.add(contentField, gbc);

        // Row 2: Buttons
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JButton addBtn = new JButton("Add Filter");
        updateBtn = new JButton("Update Selected");
        updateBtn.setEnabled(false);
        JButton delBtn = new JButton("Remove Selected");
        JButton resetBtn = new JButton("Reset Defaults");

        addBtn.addActionListener(e -> addFilter());
        updateBtn.addActionListener(e -> updateSelectedFilter());
        delBtn.addActionListener(e -> removeSelectedFilter());
        resetBtn.addActionListener(e -> resetDefaults());

        buttonRow.add(addBtn);
        buttonRow.add(updateBtn);
        buttonRow.add(delBtn);
        buttonRow.add(resetBtn);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3;
        inputsPanel.add(buttonRow, gbc);

        formPanel.add(inputsPanel, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selected = table.getSelectedRow();
                if (selected >= 0) {
                    int modelIndex = table.convertRowIndexToModel(selected);
                    InterceptionFilter f = persistenceManager.getInterceptionFilters().get(modelIndex);
                    typeBox.setSelectedItem(f.getType());
                    contentField.setText(f.getContent() != null ? f.getContent() : "");
                    enabledCheckBox.setSelected(f.isEnabled());
                    updateBtn.setEnabled(true);
                } else {
                    updateBtn.setEnabled(false);
                }
            }
        });

        add(formPanel, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    private void addFilter() {
        InterceptionFilter.FilterType type = (InterceptionFilter.FilterType) typeBox.getSelectedItem();
        String content = contentField.getText().trim();
        boolean enabled = enabledCheckBox.isSelected();

        InterceptionFilter filter = new InterceptionFilter(type, content);
        filter.setEnabled(enabled);
        persistenceManager.getInterceptionFilters().add(filter);
        persistenceManager.commitState();
        tableModel.fireTableRowsInserted(persistenceManager.getInterceptionFilters().size() - 1,
                persistenceManager.getInterceptionFilters().size() - 1);
        contentField.setText("");
    }

    private void updateSelectedFilter() {
        int selected = table.getSelectedRow();
        if (selected >= 0) {
            int modelIndex = table.convertRowIndexToModel(selected);
            InterceptionFilter f = persistenceManager.getInterceptionFilters().get(modelIndex);
            f.setType((InterceptionFilter.FilterType) typeBox.getSelectedItem());
            f.setContent(contentField.getText().trim());
            f.setEnabled(enabledCheckBox.isSelected());
            persistenceManager.commitState();
            tableModel.fireTableRowsUpdated(modelIndex, modelIndex);
        }
    }

    private void removeSelectedFilter() {
        int selected = table.getSelectedRow();
        if (selected >= 0) {
            int modelIndex = table.convertRowIndexToModel(selected);
            persistenceManager.getInterceptionFilters().remove(modelIndex);
            persistenceManager.commitState();
            tableModel.fireTableRowsDeleted(modelIndex, modelIndex);
            contentField.setText("");
            updateBtn.setEnabled(false);
        }
    }

    private void resetDefaults() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Reset interception filters to recommended defaults (ignore images/css/js and OPTIONS)?",
                "Reset Defaults", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            persistenceManager.initDefaultFilters();
            persistenceManager.commitState();
            tableModel.fireTableDataChanged();
        }
    }

    private class FilterTableModel extends AbstractTableModel {
        private final String[] columns = {"Enabled", "Filter Type", "Pattern / Value"};

        @Override
        public int getRowCount() {
            return persistenceManager.getInterceptionFilters().size();
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
            List<InterceptionFilter> list = persistenceManager.getInterceptionFilters();
            if (rowIndex < 0 || rowIndex >= list.size()) return null;
            InterceptionFilter f = list.get(rowIndex);
            switch (columnIndex) {
                case 0: return f.isEnabled();
                case 1: return f.getType() != null ? f.getType().getLabel() : "";
                case 2: return f.getContent();
                default: return "";
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            List<InterceptionFilter> list = persistenceManager.getInterceptionFilters();
            if (columnIndex == 0 && rowIndex >= 0 && rowIndex < list.size()) {
                list.get(rowIndex).setEnabled((Boolean) aValue);
                persistenceManager.commitState();
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
