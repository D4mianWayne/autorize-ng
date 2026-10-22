package com.autorize.ui;

import com.autorize.export.CsvExporter;
import com.autorize.export.HtmlExporter;
import com.autorize.export.SarifExporter;
import com.autorize.model.AutorizeConfigBundle;
import com.autorize.persistence.PersistenceManager;
import com.autorize.replay.ReplayEngine;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;

public class ConfigurationPanel extends JPanel {

    private final PersistenceManager persistenceManager;
    private final ReplayEngine replayEngine;
    private final Runnable onTableCleared;

    public ConfigurationPanel(PersistenceManager persistenceManager, ReplayEngine replayEngine, Runnable onTableCleared) {
        super(new BorderLayout(8, 8));
        this.persistenceManager = persistenceManager;
        this.replayEngine = replayEngine;
        this.onTableCleared = onTableCleared;
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel mainGrid = new JPanel(new GridLayout(3, 1, 8, 8));

        // 1. Core Engine Toggles
        JPanel engineBox = new JPanel(new GridLayout(3, 2, 8, 8));
        engineBox.setBorder(new TitledBorder("Engine Execution & Protocol Controls"));

        JToggleButton startBtn = new JToggleButton(persistenceManager.isInterceptEnabled() ? "Autorize is ON" : "Autorize is OFF",
                persistenceManager.isInterceptEnabled());
        startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD, 13f));
        startBtn.setBackground(persistenceManager.isInterceptEnabled() ? new Color(204, 255, 204) : new Color(255, 204, 204));

        startBtn.addActionListener(e -> {
            boolean enabled = startBtn.isSelected();
            persistenceManager.setInterceptEnabled(enabled);
            startBtn.setText(enabled ? "Autorize is ON" : "Autorize is OFF");
            startBtn.setBackground(enabled ? new Color(204, 255, 204) : new Color(255, 204, 204));
        });

        JButton clearBtn = new JButton("Clear Table & Traffic Stores");
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this, "Are you sure you want to clear all log entries and stored traffic?",
                    "Clear Table", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                persistenceManager.clearAllLogs();
                if (onTableCleared != null) onTableCleared.run();
            }
        });

        JCheckBox unauthCheck = new JCheckBox("Check Unauthenticated Context", persistenceManager.isCheckUnauthenticated());
        unauthCheck.addActionListener(e -> persistenceManager.setCheckUnauthenticated(unauthCheck.isSelected()));

        JCheckBox safeMethodsCheck = new JCheckBox("Safety Guard: Replay Safe Methods Only (GET/HEAD)", persistenceManager.isSafeMethodsOnly());
        safeMethodsCheck.addActionListener(e -> persistenceManager.setSafeMethodsOnly(safeMethodsCheck.isSelected()));

        JCheckBox prevent304Check = new JCheckBox("Prevent 304 Not Modified (Strip Cache Headers)", persistenceManager.isPrevent304());
        prevent304Check.addActionListener(e -> persistenceManager.setPrevent304(prevent304Check.isSelected()));

        JCheckBox ignore304Check = new JCheckBox("Ignore 304/204 Status Codes", persistenceManager.isIgnore304());
        ignore304Check.addActionListener(e -> persistenceManager.setIgnore304(ignore304Check.isSelected()));

        engineBox.add(startBtn);
        engineBox.add(clearBtn);
        engineBox.add(unauthCheck);
        engineBox.add(safeMethodsCheck);
        engineBox.add(prevent304Check);
        engineBox.add(ignore304Check);

        // 2. Burp Tool Scope Controls
        JPanel toolBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 8));
        toolBox.setBorder(new TitledBorder("Burp Tool Interception Scope & Safety"));

        JCheckBox proxyCheck = new JCheckBox("Intercept Proxy Traffic", persistenceManager.isInterceptProxy());
        proxyCheck.addActionListener(e -> persistenceManager.setInterceptProxy(proxyCheck.isSelected()));

        JCheckBox repeaterCheck = new JCheckBox("Intercept Repeater Traffic", persistenceManager.isInterceptRepeater());
        repeaterCheck.addActionListener(e -> persistenceManager.setInterceptRepeater(repeaterCheck.isSelected()));

        JCheckBox ignoreExtCheck = new JCheckBox("Ignore Extension / Scanner Traffic (Self-Loop Prevention)", persistenceManager.isIgnoreExtensions());
        ignoreExtCheck.addActionListener(e -> persistenceManager.setIgnoreExtensions(ignoreExtCheck.isSelected()));

        toolBox.add(proxyCheck);
        toolBox.add(repeaterCheck);
        toolBox.add(ignoreExtCheck);

        // 3. Export, Import & Retest Panel
        JPanel exportBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 12));
        exportBox.setBorder(new TitledBorder("Configuration Portability & Audit Reports"));

        JButton exportConfigBtn = new JButton("Export Configuration (JSON)");
        JButton importConfigBtn = new JButton("Import Configuration (JSON)");
        JButton exportHtmlBtn = new JButton("Export HTML Report");
        JButton exportCsvBtn = new JButton("Export CSV Report");
        JButton exportSarifBtn = new JButton("Export SARIF (CI/CD)");
        JButton retestAllBtn = new JButton("Retest All Requests");

        exportConfigBtn.addActionListener(e -> exportConfigJson());
        importConfigBtn.addActionListener(e -> importConfigJson());

        exportHtmlBtn.addActionListener(e -> exportFile("HTML Report (*.html)", "html", (f) -> HtmlExporter.exportToHtml(f, persistenceManager)));
        exportCsvBtn.addActionListener(e -> exportFile("CSV Report (*.csv)", "csv", (f) -> CsvExporter.exportToCsv(f, persistenceManager)));
        exportSarifBtn.addActionListener(e -> exportFile("OASIS SARIF (*.sarif)", "sarif", (f) -> SarifExporter.exportToSarif(f, persistenceManager)));

        retestAllBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this, "Retest all " + persistenceManager.getLogEntries().size() + " recorded requests across all user contexts?",
                    "Retest All", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                replayEngine.retestAll();
            }
        });

        exportBox.add(exportConfigBtn);
        exportBox.add(importConfigBtn);
        exportBox.add(exportHtmlBtn);
        exportBox.add(exportCsvBtn);
        exportBox.add(exportSarifBtn);
        exportBox.add(retestAllBtn);

        mainGrid.add(engineBox);
        mainGrid.add(toolBox);
        mainGrid.add(exportBox);
        add(mainGrid, BorderLayout.NORTH);
    }

    private void exportFile(String desc, String ext, FileExporter exporter) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export " + desc);
        chooser.setSelectedFile(new File("autorize_report." + ext));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            try {
                exporter.export(chooser.getSelectedFile());
                JOptionPane.showMessageDialog(this, "Export successfully completed to:\n" + chooser.getSelectedFile().getAbsolutePath(),
                        "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportConfigJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Autorize Configuration (JSON)");
        chooser.setSelectedFile(new File("autorize_config.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
                AutorizeConfigBundle bundle = persistenceManager.exportConfigBundle();
                mapper.writeValue(chooser.getSelectedFile(), bundle);
                JOptionPane.showMessageDialog(this, "Configuration exported successfully to:\n" + chooser.getSelectedFile().getAbsolutePath(),
                        "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importConfigJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Autorize Configuration (JSON)");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                AutorizeConfigBundle bundle = mapper.readValue(chooser.getSelectedFile(), AutorizeConfigBundle.class);
                persistenceManager.importConfigBundle(bundle);
                if (onTableCleared != null) onTableCleared.run();
                JOptionPane.showMessageDialog(this, "Configuration imported successfully!\n" +
                        "User Profiles: " + (bundle.getUserProfiles() != null ? bundle.getUserProfiles().size() : 0) +
                        "\nInterception Filters: " + (bundle.getInterceptionFilters() != null ? bundle.getInterceptionFilters().size() : 0) +
                        "\nUnauth Detectors: " + (bundle.getUnauthDetectors() != null ? bundle.getUnauthDetectors().size() : 0),
                        "Import Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    @FunctionalInterface
    private interface FileExporter {
        void export(File f) throws Exception;
    }
}
