package com.autorize.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.autorize.model.LogEntry;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MessageViewerPanel extends JPanel {

    private final MontoyaApi api;
    private final PersistenceManager persistenceManager;

    private final HttpRequestEditor origReqEditor;
    private final HttpResponseEditor origResEditor;
    private final JTabbedPane origTabs;

    private final HttpRequestEditor unauthReqEditor;
    private final HttpResponseEditor unauthResEditor;
    private final JTabbedPane unauthTabs;

    private final Map<String, UserViewerPair> userEditors = new ConcurrentHashMap<>();
    private final Map<String, JTabbedPane> userTabbedPanes = new ConcurrentHashMap<>();

    // Options Controls
    private final JCheckBox showOrigCheck;
    private final JCheckBox showUnauthCheck;
    private final JCheckBox showUsersCheck;
    private final JRadioButton splitViewRadio;
    private final JRadioButton tabbedViewRadio;
    private final JButton maximizeBtn;

    private final JPanel containerPanel;
    private boolean isMaximized = false;
    private Component maximizedComponent = null;

    private static class UserViewerPair {
        final HttpRequestEditor reqEditor;
        final HttpResponseEditor resEditor;

        UserViewerPair(HttpRequestEditor reqEditor, HttpResponseEditor resEditor) {
            this.reqEditor = reqEditor;
            this.resEditor = resEditor;
        }
    }

    public MessageViewerPanel(MontoyaApi api, PersistenceManager persistenceManager) {
        super(new BorderLayout(4, 4));
        this.api = api;
        this.persistenceManager = persistenceManager;

        // 1. Initialize Message Editors
        origReqEditor = api.userInterface().createHttpRequestEditor();
        origResEditor = api.userInterface().createHttpResponseEditor();
        origTabs = new JTabbedPane();
        origTabs.addTab("Original Request", origReqEditor.uiComponent());
        origTabs.addTab("Original Response", origResEditor.uiComponent());

        unauthReqEditor = api.userInterface().createHttpRequestEditor();
        unauthResEditor = api.userInterface().createHttpResponseEditor();
        unauthTabs = new JTabbedPane();
        unauthTabs.addTab("Unauthenticated Request", unauthReqEditor.uiComponent());
        unauthTabs.addTab("Unauthenticated Response", unauthResEditor.uiComponent());

        // 2. Options Toolbar
        JPanel optionsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        optionsBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));

        optionsBar.add(new JLabel("Message Blocks to Show:"));
        showOrigCheck = new JCheckBox("Original", true);
        showUnauthCheck = new JCheckBox("Unauthenticated", true);
        showUsersCheck = new JCheckBox("User Sessions", true);

        optionsBar.add(showOrigCheck);
        optionsBar.add(showUnauthCheck);
        optionsBar.add(showUsersCheck);

        optionsBar.add(new JSeparator(SwingConstants.VERTICAL));
        optionsBar.add(new JLabel("Layout:"));

        splitViewRadio = new JRadioButton("Split View", false);
        tabbedViewRadio = new JRadioButton("Tabbed View (Full Height)", true);
        ButtonGroup group = new ButtonGroup();
        group.add(splitViewRadio);
        group.add(tabbedViewRadio);

        optionsBar.add(tabbedViewRadio);
        optionsBar.add(splitViewRadio);

        optionsBar.add(new JSeparator(SwingConstants.VERTICAL));
        maximizeBtn = new JButton("Maximize Current Block");
        optionsBar.add(maximizeBtn);

        containerPanel = new JPanel(new BorderLayout());

        // Listeners for view rebuilding
        showOrigCheck.addActionListener(e -> rebuildView());
        showUnauthCheck.addActionListener(e -> rebuildView());
        showUsersCheck.addActionListener(e -> rebuildView());
        splitViewRadio.addActionListener(e -> rebuildView());
        tabbedViewRadio.addActionListener(e -> rebuildView());

        maximizeBtn.addActionListener(e -> toggleMaximize());

        refreshUserTabs();
        rebuildView();

        add(optionsBar, BorderLayout.NORTH);
        add(containerPanel, BorderLayout.CENTER);
    }

    public void refreshUserTabs() {
        for (UserProfile user : persistenceManager.getUserProfiles()) {
            userEditors.computeIfAbsent(user.getId(), id -> {
                HttpRequestEditor req = api.userInterface().createHttpRequestEditor();
                HttpResponseEditor res = api.userInterface().createHttpResponseEditor();
                return new UserViewerPair(req, res);
            });

            userTabbedPanes.computeIfAbsent(user.getId(), id -> {
                UserViewerPair pair = userEditors.get(id);
                JTabbedPane singleUserTabs = new JTabbedPane();
                singleUserTabs.addTab(user.getName() + " Request", pair.reqEditor.uiComponent());
                singleUserTabs.addTab(user.getName() + " Response", pair.resEditor.uiComponent());
                return singleUserTabs;
            });

            // Update title if user was renamed
            JTabbedPane userPane = userTabbedPanes.get(user.getId());
            if (userPane != null && userPane.getTabCount() >= 2) {
                userPane.setTitleAt(0, user.getName() + " Request");
                userPane.setTitleAt(1, user.getName() + " Response");
            }
        }
        rebuildView();
    }

    public void rebuildView() {
        if (isMaximized) {
            return;
        }

        containerPanel.removeAll();

        List<ComponentBlock> activeBlocks = new ArrayList<>();
        if (showOrigCheck.isSelected()) {
            activeBlocks.add(new ComponentBlock("Original (Baseline)", origTabs));
        }
        if (showUnauthCheck.isSelected()) {
            activeBlocks.add(new ComponentBlock("Unauthenticated", unauthTabs));
        }
        if (showUsersCheck.isSelected()) {
            for (UserProfile user : persistenceManager.getUserProfiles()) {
                JTabbedPane pane = userTabbedPanes.get(user.getId());
                if (pane != null) {
                    activeBlocks.add(new ComponentBlock(user.getName(), pane));
                }
            }
        }

        if (activeBlocks.isEmpty()) {
            JPanel empty = new JPanel(new GridBagLayout());
            empty.add(new JLabel("No message blocks selected. Use the checkboxes above to display traffic viewers."));
            containerPanel.add(empty, BorderLayout.CENTER);
        } else if (tabbedViewRadio.isSelected()) {
            // Tabbed View: Full height for the active tab!
            JTabbedPane mainTabs = new JTabbedPane();
            for (ComponentBlock block : activeBlocks) {
                mainTabs.addTab(block.title, block.component);
            }
            containerPanel.add(mainTabs, BorderLayout.CENTER);
        } else {
            // Split / Stacked View
            if (activeBlocks.size() == 1) {
                containerPanel.add(activeBlocks.get(0).component, BorderLayout.CENTER);
            } else if (activeBlocks.size() == 2) {
                JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                        activeBlocks.get(0).component, activeBlocks.get(1).component);
                split.setResizeWeight(0.5);
                containerPanel.add(split, BorderLayout.CENTER);
            } else {
                JPanel grid = new JPanel(new GridLayout(activeBlocks.size(), 1, 4, 4));
                for (ComponentBlock block : activeBlocks) {
                    grid.add(block.component);
                }
                containerPanel.add(grid, BorderLayout.CENTER);
            }
        }

        containerPanel.revalidate();
        containerPanel.repaint();
    }

    private void toggleMaximize() {
        if (!isMaximized) {
            Component target = null;
            if (containerPanel.getComponentCount() > 0) {
                Component c = containerPanel.getComponent(0);
                if (c instanceof JTabbedPane tp) {
                    target = tp.getSelectedComponent();
                } else if (c instanceof JSplitPane sp) {
                    target = sp.getLeftComponent();
                } else {
                    target = c;
                }
            }
            if (target != null) {
                isMaximized = true;
                maximizedComponent = target;
                containerPanel.removeAll();
                containerPanel.add(target, BorderLayout.CENTER);
                maximizeBtn.setText("Restore View Layout");
                containerPanel.revalidate();
                containerPanel.repaint();
            }
        } else {
            isMaximized = false;
            maximizedComponent = null;
            maximizeBtn.setText("Maximize Current Block");
            rebuildView();
        }
    }

    public void displayEntry(LogEntry entry) {
        if (entry == null) return;

        // Load Original
        HttpRequestResponse origTx = persistenceManager.getOriginalTraffic(entry.getOrigTrafficIndex());
        if (origTx != null) {
            origReqEditor.setRequest(origTx.request());
            if (origTx.response() != null) origResEditor.setResponse(origTx.response());
        }

        // Load Unauthenticated
        HttpRequestResponse unauthTx = persistenceManager.getUnauthTraffic(entry.getUnauthTrafficIndex());
        if (unauthTx != null) {
            unauthReqEditor.setRequest(unauthTx.request());
            if (unauthTx.response() != null) unauthResEditor.setResponse(unauthTx.response());
        }

        // Load Each User
        for (UserProfile user : persistenceManager.getUserProfiles()) {
            UserViewerPair pair = userEditors.get(user.getId());
            if (pair == null) continue;

            LogEntry.UserResult userResult = entry.getUserResult(user.getId());
            if (userResult != null && userResult.getUserTrafficIndex() >= 0) {
                HttpRequestResponse userTx = persistenceManager.getUserTraffic(user.getId(), userResult.getUserTrafficIndex());
                if (userTx != null) {
                    pair.reqEditor.setRequest(userTx.request());
                    if (userTx.response() != null) pair.resEditor.setResponse(userTx.response());
                }
            }
        }
    }

    private static class ComponentBlock {
        final String title;
        final Component component;

        ComponentBlock(String title, Component component) {
            this.title = title;
            this.component = component;
        }
    }
}
