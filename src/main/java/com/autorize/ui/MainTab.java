package com.autorize.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.autorize.auth.AuthBroker;
import com.autorize.model.EnforcementStatus;
import com.autorize.model.LogEntry;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;
import com.autorize.replay.ReplayEngine;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

public class MainTab extends JPanel {

    private final MontoyaApi api;
    private final PersistenceManager persistenceManager;
    private final ReplayEngine replayEngine;
    private final AuthBroker authBroker;

    private final LogTableModel tableModel;
    private final JTable logTable;
    private final TableRowSorter<LogTableModel> tableSorter;
    private final MessageViewerPanel messageViewerPanel;
    private final UserManagementPanel userManagementPanel;

    // Filter controls
    private final JCheckBox showBypassed;
    private final JCheckBox showEnforced;
    private final JCheckBox showAmbiguous;
    private final JTextField filterField;
    private final JLabel rowCountLabel;

    public MainTab(MontoyaApi api, PersistenceManager persistenceManager, ReplayEngine replayEngine, AuthBroker authBroker) {
        super(new BorderLayout());
        this.api = api;
        this.persistenceManager = persistenceManager;
        this.replayEngine = replayEngine;
        this.authBroker = authBroker;

        // 1. Table & Model Setup
        tableModel = new LogTableModel(persistenceManager);
        tableSorter = new TableRowSorter<>(tableModel);
        logTable = new JTable(tableModel);
        logTable.setRowSorter(tableSorter);
        logTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        // Apply Status Cell Renderers
        StatusCellRenderer statusRenderer = new StatusCellRenderer();
        for (int i = 0; i < logTable.getColumnCount(); i++) {
            if (logTable.getColumnClass(i) == EnforcementStatus.class) {
                logTable.getColumnModel().getColumn(i).setCellRenderer(statusRenderer);
            }
        }

        // Set column widths
        adjustColumnWidths();

        // 2. Viewers & Panels
        messageViewerPanel = new MessageViewerPanel(api, persistenceManager);

        userManagementPanel = new UserManagementPanel(persistenceManager, authBroker, this::getSelectedOrLastTraffic, () -> {
            tableModel.fireTableStructureChanged();
            messageViewerPanel.refreshUserTabs();
            adjustColumnWidths();
            reapplyRenderers();
            applyTableFilter();
        });

        ConfigurationPanel configPanel = new ConfigurationPanel(persistenceManager, replayEngine, () -> {
            tableModel.fireTableDataChanged();
            messageViewerPanel.refreshUserTabs();
            adjustColumnWidths();
            reapplyRenderers();
            applyTableFilter();
        });

        FilterConfigPanel filterConfigPanel = new FilterConfigPanel(persistenceManager);
        DetectorConfigPanel unauthDetectorPanel = new DetectorConfigPanel(
                "Unauthenticated Enforcement Fingerprints (Baseline)",
                persistenceManager.getUnauthDetectors(),
                false,
                null,
                persistenceManager::commitState,
                persistenceManager::initDefaultUnauthDetectors
        );

        // 3. Selection Listener -> update viewers
        logTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = logTable.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = logTable.convertRowIndexToModel(selectedRow);
                    LogEntry entry = tableModel.getEntryAt(modelRow);
                    messageViewerPanel.displayEntry(entry);
                }
            }
        });

        // 4. Quick Status & Search Filter Bar Setup
        showBypassed = new JCheckBox("Bypassed!", true);
        showEnforced = new JCheckBox("Enforced!", true);
        showAmbiguous = new JCheckBox("Is enforced???", true);
        filterField = new JTextField(14);
        rowCountLabel = new JLabel("(Showing 0 / 0)");

        showBypassed.addItemListener(e -> applyTableFilter());
        showEnforced.addItemListener(e -> applyTableFilter());
        showAmbiguous.addItemListener(e -> applyTableFilter());

        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyTableFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyTableFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyTableFilter(); }
        });

        JButton clearFilterBtn = new JButton("Clear Filters");
        clearFilterBtn.addActionListener(e -> {
            showBypassed.setSelected(true);
            showEnforced.setSelected(true);
            showAmbiguous.setSelected(true);
            filterField.setText("");
            applyTableFilter();
        });

        // 5. Context Menu & Key Bindings
        setupContextMenu();

        // 6. Connect ReplayEngine notification to table update
        replayEngine.setOnLogEntryAdded(entry -> {
            int row = persistenceManager.getLogEntries().size() - 1;
            tableModel.fireTableRowsInserted(row, row);
            updateRowCountLabel();
        });

        // 7. Layout Construction (SplitPane)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.55);

        // Left Component: Log Table + Filter Bar
        JPanel leftPanel = new JPanel(new BorderLayout(4, 4));
        leftPanel.add(new JScrollPane(logTable), BorderLayout.CENTER);

        JPanel statusFilterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        statusFilterBar.add(new JLabel("Quick Filter:"));
        statusFilterBar.add(showBypassed);
        statusFilterBar.add(showEnforced);
        statusFilterBar.add(showAmbiguous);
        statusFilterBar.add(Box.createHorizontalStrut(8));
        statusFilterBar.add(new JLabel("URL/Method:"));
        statusFilterBar.add(filterField);
        statusFilterBar.add(clearFilterBtn);
        statusFilterBar.add(Box.createHorizontalStrut(8));
        statusFilterBar.add(rowCountLabel);
        leftPanel.add(statusFilterBar, BorderLayout.SOUTH);

        // Right Component: Tabbed Container (Viewers, Config, Users, Filters)
        JTabbedPane rightTabs = new JTabbedPane();
        rightTabs.addTab("Request / Response Viewers", messageViewerPanel);
        rightTabs.addTab("Configuration", configPanel);
        rightTabs.addTab("User Profiles", userManagementPanel);
        rightTabs.addTab("Interception Filters", filterConfigPanel);
        rightTabs.addTab("Unauth Detectors", unauthDetectorPanel);

        mainSplit.setLeftComponent(leftPanel);
        mainSplit.setRightComponent(rightTabs);

        add(mainSplit, BorderLayout.CENTER);
        updateRowCountLabel();
    }

    private void applyTableFilter() {
        boolean bypassed = showBypassed.isSelected();
        boolean enforced = showEnforced.isSelected();
        boolean ambiguous = showAmbiguous.isSelected();
        String query = filterField.getText().trim().toLowerCase();

        tableSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends LogTableModel, ? extends Integer> entry) {
                int modelRow = entry.getIdentifier();
                LogEntry log = tableModel.getEntryAt(modelRow);
                if (log == null) return false;

                // 1. Text Search Filter (URL & Method)
                if (!query.isEmpty()) {
                    boolean matchesUrl = log.getUrl() != null && log.getUrl().toLowerCase().contains(query);
                    boolean matchesMethod = log.getMethod() != null && log.getMethod().toLowerCase().contains(query);
                    if (!matchesUrl && !matchesMethod) {
                        return false;
                    }
                }

                // 2. Status Match: check if any active status (Unauth or User result) matches checked filters
                if (bypassed && enforced && ambiguous) {
                    return true;
                }
                if (!bypassed && !enforced && !ambiguous) {
                    return false;
                }

                // Check Unauth Status
                if (log.getUnauthStatus() != null && log.getUnauthStatus() != EnforcementStatus.DISABLED) {
                    if (bypassed && log.getUnauthStatus() == EnforcementStatus.BYPASSED) return true;
                    if (enforced && log.getUnauthStatus() == EnforcementStatus.ENFORCED) return true;
                    if (ambiguous && log.getUnauthStatus() == EnforcementStatus.AMBIGUOUS) return true;
                }

                // Check each User result status
                for (var uRes : log.getUserResults().values()) {
                    if (uRes.getStatus() != null && uRes.getStatus() != EnforcementStatus.DISABLED) {
                        if (bypassed && uRes.getStatus() == EnforcementStatus.BYPASSED) return true;
                        if (enforced && uRes.getStatus() == EnforcementStatus.ENFORCED) return true;
                        if (ambiguous && uRes.getStatus() == EnforcementStatus.AMBIGUOUS) return true;
                    }
                }

                return false;
            }
        });

        updateRowCountLabel();
    }

    private void updateRowCountLabel() {
        rowCountLabel.setText(String.format("(Showing %d / %d)", logTable.getRowCount(), tableModel.getRowCount()));
    }

    private void adjustColumnWidths() {
        if (logTable.getColumnCount() >= 6) {
            logTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // ID
            logTable.getColumnModel().getColumn(1).setPreferredWidth(70);  // Method
            logTable.getColumnModel().getColumn(2).setPreferredWidth(280); // URL
            logTable.getColumnModel().getColumn(3).setPreferredWidth(75);  // Orig Len
            logTable.getColumnModel().getColumn(4).setPreferredWidth(85);  // Unauth Len
            logTable.getColumnModel().getColumn(5).setPreferredWidth(110); // Unauth Status
        }
    }

    private void reapplyRenderers() {
        StatusCellRenderer renderer = new StatusCellRenderer();
        for (int i = 0; i < logTable.getColumnCount(); i++) {
            if (logTable.getColumnClass(i) == EnforcementStatus.class) {
                logTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
            }
        }
    }

    private void setupContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem sendOrigToRepeater = new JMenuItem("Send Original Request to Repeater");
        sendOrigToRepeater.addActionListener(e -> {
            LogEntry entry = getSelectedEntry();
            if (entry != null) {
                HttpRequestResponse tx = persistenceManager.getOriginalTraffic(entry.getOrigTrafficIndex());
                if (tx != null) {
                    api.repeater().sendToRepeater(tx.request(), "Autorize: Orig #" + entry.getId());
                }
            }
        });

        JMenuItem sendUnauthToRepeater = new JMenuItem("Send Unauthenticated Request to Repeater");
        sendUnauthToRepeater.addActionListener(e -> {
            LogEntry entry = getSelectedEntry();
            if (entry != null && entry.getUnauthTrafficIndex() >= 0) {
                HttpRequestResponse tx = persistenceManager.getUnauthTraffic(entry.getUnauthTrafficIndex());
                if (tx != null) {
                    api.repeater().sendToRepeater(tx.request(), "Autorize: Unauth #" + entry.getId());
                }
            }
        });

        JMenuItem sendResponsesToComparer = new JMenuItem("Send Responses to Comparer");
        sendResponsesToComparer.addActionListener(e -> {
            LogEntry entry = getSelectedEntry();
            if (entry != null) {
                HttpRequestResponse origTx = persistenceManager.getOriginalTraffic(entry.getOrigTrafficIndex());
                if (origTx != null && origTx.response() != null) {
                    api.comparer().sendToComparer(origTx.response().toByteArray());
                }
                HttpRequestResponse unauthTx = persistenceManager.getUnauthTraffic(entry.getUnauthTrafficIndex());
                if (unauthTx != null && unauthTx.response() != null) {
                    api.comparer().sendToComparer(unauthTx.response().toByteArray());
                }
            }
        });

        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        copyUrlItem.addActionListener(e -> {
            LogEntry entry = getSelectedEntry();
            if (entry != null && entry.getUrl() != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(entry.getUrl()), null);
            }
        });

        JMenuItem retestItem = new JMenuItem("Retest Selected Request(s)");
        retestItem.addActionListener(e -> {
            int[] selectedRows = logTable.getSelectedRows();
            for (int row : selectedRows) {
                int modelRow = logTable.convertRowIndexToModel(row);
                LogEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null) {
                    replayEngine.retest(entry);
                }
            }
        });

        JMenuItem deleteItem = new JMenuItem("Delete Selected Request(s)");
        deleteItem.addActionListener(e -> deleteSelectedRequests());

        // Keyboard Shortcut: Delete Key
        logTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteSelectedRows");
        logTable.getActionMap().put("deleteSelectedRows", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                deleteSelectedRequests();
            }
        });

        logTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger() || e.getButton() == MouseEvent.BUTTON3) {
                    int row = logTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !logTable.isRowSelected(row)) {
                        logTable.setRowSelectionInterval(row, row);
                    }

                    menu.removeAll();
                    menu.add(sendOrigToRepeater);
                    menu.add(sendUnauthToRepeater);

                    // Dynamic "Send Modified Request to Repeater" (per user)
                    List<UserProfile> users = persistenceManager.getUserProfiles();
                    if (users.size() == 1) {
                        UserProfile u = users.get(0);
                        JMenuItem sendUserItem = new JMenuItem("Send Modified Request (" + u.getName() + ") to Repeater");
                        sendUserItem.addActionListener(ev -> sendUserRequestToRepeater(u));
                        menu.add(sendUserItem);
                    } else if (users.size() > 1) {
                        JMenu sendUserMenu = new JMenu("Send Modified Request to Repeater");
                        for (UserProfile u : users) {
                            JMenuItem userItem = new JMenuItem(u.getName());
                            userItem.addActionListener(ev -> sendUserRequestToRepeater(u));
                            sendUserMenu.add(userItem);
                        }
                        menu.add(sendUserMenu);
                    }

                    menu.addSeparator();
                    menu.add(sendResponsesToComparer);
                    menu.add(copyUrlItem);
                    menu.addSeparator();
                    menu.add(retestItem);
                    menu.add(deleteItem);

                    menu.show(logTable, e.getX(), e.getY());
                }
            }
        });
    }

    private void sendUserRequestToRepeater(UserProfile user) {
        LogEntry entry = getSelectedEntry();
        if (entry != null) {
            var uRes = entry.getUserResult(user.getId());
            if (uRes != null && uRes.getUserTrafficIndex() >= 0) {
                HttpRequestResponse tx = persistenceManager.getUserTraffic(user.getId(), uRes.getUserTrafficIndex());
                if (tx != null && tx.request() != null) {
                    api.repeater().sendToRepeater(tx.request(), "Autorize: " + user.getName() + " #" + entry.getId());
                }
            }
        }
    }

    private void deleteSelectedRequests() {
        int[] selectedRows = logTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to delete " + selectedRows.length + " selected request(s)?",
                "Delete Requests", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            List<LogEntry> toDelete = new ArrayList<>();
            for (int r : selectedRows) {
                int modelRow = logTable.convertRowIndexToModel(r);
                LogEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null) {
                    toDelete.add(entry);
                }
            }
            persistenceManager.removeLogEntries(toDelete);
            tableModel.fireTableDataChanged();
            applyTableFilter();
        }
    }

    private LogEntry getSelectedEntry() {
        int selected = logTable.getSelectedRow();
        if (selected >= 0) {
            int modelRow = logTable.convertRowIndexToModel(selected);
            return tableModel.getEntryAt(modelRow);
        }
        return null;
    }

    public HttpRequestResponse getSelectedOrLastTraffic() {
        LogEntry entry = getSelectedEntry();
        if (entry != null) {
            HttpRequestResponse tx = persistenceManager.getOriginalTraffic(entry.getOrigTrafficIndex());
            if (tx != null) return tx;
        }
        return replayEngine.getLastInterceptedTx();
    }
}
