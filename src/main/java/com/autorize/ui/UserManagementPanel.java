package com.autorize.ui;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.autorize.auth.AuthBroker;
import com.autorize.auth.JwtInspector;
import com.autorize.auth.SessionHealthChecker;
import com.autorize.model.AuthMode;
import com.autorize.model.EnforcementDetector;
import com.autorize.model.MatchReplaceRule;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

public class UserManagementPanel extends JPanel {

    private final PersistenceManager persistenceManager;
    private final AuthBroker authBroker;
    private final Supplier<HttpRequestResponse> trafficSupplier;
    private final JTabbedPane userTabs;
    private final Runnable onStructureChanged;

    public UserManagementPanel(PersistenceManager persistenceManager,
                               AuthBroker authBroker,
                               Supplier<HttpRequestResponse> trafficSupplier,
                               Runnable onStructureChanged) {
        super(new BorderLayout(8, 8));
        this.persistenceManager = persistenceManager;
        this.authBroker = authBroker;
        this.trafficSupplier = trafficSupplier;
        this.onStructureChanged = onStructureChanged;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Top Toolbar
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton addUserBtn = new JButton("Add User Profile");
        JButton renameUserBtn = new JButton("Rename User");
        JButton duplicateUserBtn = new JButton("Duplicate User");
        JButton removeUserBtn = new JButton("Remove User");

        addUserBtn.addActionListener(e -> promptAddUser());
        renameUserBtn.addActionListener(e -> promptRenameUser());
        duplicateUserBtn.addActionListener(e -> duplicateSelectedUser());
        removeUserBtn.addActionListener(e -> promptRemoveUser());

        topBar.add(addUserBtn);
        topBar.add(renameUserBtn);
        topBar.add(duplicateUserBtn);
        topBar.add(removeUserBtn);

        userTabs = new JTabbedPane();
        refreshTabs();

        add(topBar, BorderLayout.NORTH);
        add(userTabs, BorderLayout.CENTER);
    }

    public void refreshTabs() {
        int selectedIndex = Math.max(0, userTabs.getSelectedIndex());
        userTabs.removeAll();
        for (UserProfile user : persistenceManager.getUserProfiles()) {
            userTabs.addTab(user.getName(), createSingleUserPanel(user));
        }
        if (selectedIndex < userTabs.getTabCount()) {
            userTabs.setSelectedIndex(selectedIndex);
        }
    }

    private JPanel createSingleUserPanel(UserProfile user) {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JTabbedPane subTabs = new JTabbedPane();

        // Subtab 1: Authentication
        subTabs.addTab("Authentication", createAuthSubPanel(user));

        // Subtab 2: Enforcement Detectors
        DetectorConfigPanel userDetectorsPanel = new DetectorConfigPanel(
                "Enforcement Fingerprints for " + user.getName(),
                user.getEnforcementDetectors(),
                user.isDetectorAndLogic(),
                user::setDetectorAndLogic,
                persistenceManager::commitState,
                () -> persistenceManager.initDefaultUserDetectors(user)
        );
        subTabs.addTab("Enforcement Detectors", userDetectorsPanel);

        // Subtab 3: Match & Replace
        MatchReplacePanel matchReplacePanel = new MatchReplacePanel(
                user.getMatchReplaceRules(),
                persistenceManager::commitState
        );
        subTabs.addTab("Match & Replace", matchReplacePanel);

        panel.add(subTabs, BorderLayout.CENTER);
        return panel;
    }

    private JScrollPane createAuthSubPanel(UserProfile user) {
        JPanel authContainer = new JPanel();
        authContainer.setLayout(new BoxLayout(authContainer, BoxLayout.Y_AXIS));
        authContainer.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // 1. Live Session Health & JWT Diagnostics Toolbar
        JPanel healthBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        healthBar.setBorder(new TitledBorder("Session Health & Live Diagnostics (2026 Engine)"));

        JLabel healthBadge = new JLabel("● Session Status: Not Probed Yet");
        healthBadge.setFont(healthBadge.getFont().deriveFont(Font.BOLD, 12f));
        healthBadge.setForeground(Color.DARK_GRAY);

        JButton testHealthBtn = new JButton("Test Session Liveness");
        JButton refreshNowBtn = new JButton("Refresh / Re-Login Now");
        JButton inspectJwtBtn = new JButton("Inspect JWT Token");

        healthBar.add(healthBadge);
        healthBar.add(testHealthBtn);
        healthBar.add(refreshNowBtn);
        healthBar.add(inspectJwtBtn);
        authContainer.add(healthBar);

        // 2. Preset Templates Selector
        JPanel presetBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        presetBar.setBorder(new TitledBorder("Quick Configuration Presets"));
        presetBar.add(new JLabel("Apply Template:"));

        JComboBox<String> presetBox = new JComboBox<>(new String[]{
                "-- Select a Preset to Pre-fill --",
                "1. Standard Bearer JWT (Authorization: Bearer <token>)",
                "2. Cookie Session (Cookie: session=...; XSRF-TOKEN=...)",
                "3. OAuth 2.0 (Refresh Token Flow with Rotation)",
                "4. OAuth 2.0 (Client Credentials Grant)",
                "5. RFC 9449 DPoP (Proof-of-Possession Token)",
                "6. API Key (X-API-Key: <key>)",
                "7. Automated Macro Re-Login (POST /api/login)"
        });
        presetBar.add(presetBox);
        authContainer.add(presetBar);

        // 3. Auth Engine Mode Selection
        JPanel modeBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        modeBox.setBorder(new TitledBorder("Authentication Engine Mode"));
        modeBox.add(new JLabel("Mode:"));
        JComboBox<AuthMode> modeDropdown = new JComboBox<>(AuthMode.values());
        modeDropdown.setSelectedItem(user.getAuthMode());
        modeBox.add(modeDropdown);
        authContainer.add(modeBox);

        // 4. Replacement Headers & Cookies Area
        JPanel headersBox = new JPanel(new BorderLayout(6, 6));
        headersBox.setBorder(new TitledBorder("Replacement Headers / Cookies (Injected into replayed requests)"));

        JPanel fetchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton fetchCookiesBtn = new JButton("Fetch Cookies Header");
        JButton fetchAuthBtn = new JButton("Fetch Authorization Header");
        JButton fetchBothBtn = new JButton("Fetch Both (Cookie + Auth)");
        JButton clearHeadersBtn = new JButton("Clear Headers");

        fetchBar.add(new JLabel("From Selected/Last Request:"));
        fetchBar.add(fetchCookiesBtn);
        fetchBar.add(fetchAuthBtn);
        fetchBar.add(fetchBothBtn);
        fetchBar.add(clearHeadersBtn);
        headersBox.add(fetchBar, BorderLayout.NORTH);

        JTextArea headersArea = new JTextArea(user.getHeadersText() != null ? user.getHeadersText() : "", 6, 40);
        headersArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        headersArea.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setHeadersText(headersArea.getText());
            persistenceManager.commitState();
        }));
        headersBox.add(new JScrollPane(headersArea), BorderLayout.CENTER);
        authContainer.add(headersBox);

        // 5. Dynamic OAuth 2.0 / 2.1 Settings Card
        JPanel oauthPanel = new JPanel(new GridLayout(5, 2, 6, 6));
        oauthPanel.setBorder(new TitledBorder("OAuth 2.0 / 2.1 Auto-Token Refresh Settings"));

        JTextField tokenEndpointField = new JTextField(user.getTokenEndpoint());
        JTextField clientIdField = new JTextField(user.getClientId());
        JTextField clientSecretField = new JPasswordField(user.getClientSecret());
        JTextField refreshTokenField = new JTextField(user.getRefreshToken());
        JLabel dpopNonceLabel = new JLabel(user.getServerDPoPNonce().isEmpty() ? "<None cached>" : user.getServerDPoPNonce());

        tokenEndpointField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setTokenEndpoint(tokenEndpointField.getText().trim());
            persistenceManager.commitState();
        }));
        clientIdField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setClientId(clientIdField.getText().trim());
            persistenceManager.commitState();
        }));
        clientSecretField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setClientSecret(clientSecretField.getText().trim());
            persistenceManager.commitState();
        }));
        refreshTokenField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setRefreshToken(refreshTokenField.getText().trim());
            persistenceManager.commitState();
        }));

        oauthPanel.add(new JLabel("Token Endpoint URL:"));
        oauthPanel.add(tokenEndpointField);
        oauthPanel.add(new JLabel("Client ID:"));
        oauthPanel.add(clientIdField);
        oauthPanel.add(new JLabel("Client Secret:"));
        oauthPanel.add(clientSecretField);
        oauthPanel.add(new JLabel("Refresh Token:"));
        oauthPanel.add(refreshTokenField);
        oauthPanel.add(new JLabel("Last DPoP-Nonce (RFC 9449):"));
        oauthPanel.add(dpopNonceLabel);
        authContainer.add(oauthPanel);

        // 6. Automated Macro Re-Login Settings Card
        JPanel macroPanel = new JPanel(new GridBagLayout());
        macroPanel.setBorder(new TitledBorder("Automated Macro Re-Login Settings (Scripted Login for SPAs/APIs)"));
        GridBagConstraints mgbc = new GridBagConstraints();
        mgbc.insets = new Insets(3, 4, 3, 4);
        mgbc.fill = GridBagConstraints.HORIZONTAL;

        JTextField loginEndpointField = new JTextField(user.getLoginEndpoint());
        JComboBox<String> loginMethodBox = new JComboBox<>(new String[]{"POST", "PUT", "GET"});
        loginMethodBox.setSelectedItem(user.getLoginMethod());
        JComboBox<String> loginContentTypeBox = new JComboBox<>(new String[]{"application/json", "application/x-www-form-urlencoded"});
        loginContentTypeBox.setSelectedItem(user.getLoginContentType());
        JTextArea loginBodyArea = new JTextArea(user.getLoginRequestBody(), 3, 30);
        loginBodyArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JComboBox<String> extractTypeBox = new JComboBox<>(new String[]{"JSON_FIELD", "SET_COOKIE", "HEADER"});
        extractTypeBox.setSelectedItem(user.getTokenExtractionType());
        JTextField extractPathField = new JTextField(user.getTokenExtractionPath());
        JTextField destHeaderField = new JTextField(user.getTokenDestinationHeader());

        loginEndpointField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setLoginEndpoint(loginEndpointField.getText().trim());
            persistenceManager.commitState();
        }));
        loginMethodBox.addActionListener(e -> {
            user.setLoginMethod((String) loginMethodBox.getSelectedItem());
            persistenceManager.commitState();
        });
        loginContentTypeBox.addActionListener(e -> {
            user.setLoginContentType((String) loginContentTypeBox.getSelectedItem());
            persistenceManager.commitState();
        });
        loginBodyArea.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setLoginRequestBody(loginBodyArea.getText());
            persistenceManager.commitState();
        }));
        extractTypeBox.addActionListener(e -> {
            user.setTokenExtractionType((String) extractTypeBox.getSelectedItem());
            persistenceManager.commitState();
        });
        extractPathField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setTokenExtractionPath(extractPathField.getText().trim());
            persistenceManager.commitState();
        }));
        destHeaderField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setTokenDestinationHeader(destHeaderField.getText().trim());
            persistenceManager.commitState();
        }));

        mgbc.gridx = 0; mgbc.gridy = 0; macroPanel.add(new JLabel("Login Endpoint URL:"), mgbc);
        mgbc.gridx = 1; mgbc.weightx = 1.0; macroPanel.add(loginEndpointField, mgbc);

        mgbc.gridx = 0; mgbc.gridy = 1; mgbc.weightx = 0; macroPanel.add(new JLabel("Method & Content-Type:"), mgbc);
        JPanel mcPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        mcPanel.add(loginMethodBox);
        mcPanel.add(loginContentTypeBox);
        mgbc.gridx = 1; macroPanel.add(mcPanel, mgbc);

        mgbc.gridx = 0; mgbc.gridy = 2; macroPanel.add(new JLabel("Login Request Body:"), mgbc);
        mgbc.gridx = 1; macroPanel.add(new JScrollPane(loginBodyArea), mgbc);

        mgbc.gridx = 0; mgbc.gridy = 3; macroPanel.add(new JLabel("Token Extraction (Type & Path):"), mgbc);
        JPanel epPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        epPanel.add(extractTypeBox);
        epPanel.add(new JLabel("Key/Path:"));
        epPanel.add(extractPathField);
        mgbc.gridx = 1; macroPanel.add(epPanel, mgbc);

        mgbc.gridx = 0; mgbc.gridy = 4; macroPanel.add(new JLabel("Destination Header Template:"), mgbc);
        mgbc.gridx = 1; macroPanel.add(destHeaderField, mgbc);

        authContainer.add(macroPanel);

        // 7. Protocol Security & Health Check Probe Settings
        JPanel protoPanel = new JPanel(new GridLayout(2, 2, 8, 4));
        protoPanel.setBorder(new TitledBorder("Protocol Security & Health Probe"));

        JCheckBox dpopCheck = new JCheckBox("Enable RFC 9449 DPoP Proof Signing", user.isDpopEnabled());
        dpopCheck.addActionListener(e -> {
            user.setDpopEnabled(dpopCheck.isSelected());
            persistenceManager.commitState();
        });

        JCheckBox csrfCheck = new JCheckBox("Sync Anti-CSRF Token", user.isSyncCsrf());
        csrfCheck.addActionListener(e -> {
            user.setSyncCsrf(csrfCheck.isSelected());
            persistenceManager.commitState();
        });

        JTextField probeUrlField = new JTextField(user.getHealthCheckEndpoint());
        probeUrlField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            user.setHealthCheckEndpoint(probeUrlField.getText().trim());
            persistenceManager.commitState();
        }));

        protoPanel.add(dpopCheck);
        protoPanel.add(csrfCheck);
        protoPanel.add(new JLabel("Health Probe URL (e.g. /api/me):"));
        protoPanel.add(probeUrlField);
        authContainer.add(protoPanel);

        // Visibility controller for dynamic cards
        Runnable updateCardVisibility = () -> {
            AuthMode mode = (AuthMode) modeDropdown.getSelectedItem();
            boolean isOauth = (mode == AuthMode.OAUTH2_REFRESH || mode == AuthMode.OAUTH2_CLIENT_CREDENTIALS || mode == AuthMode.DPOP_OAUTH2);
            boolean isMacro = (mode == AuthMode.CUSTOM_LOGIN);

            oauthPanel.setVisible(isOauth);
            macroPanel.setVisible(isMacro);
            authContainer.revalidate();
            authContainer.repaint();
        };

        modeDropdown.addActionListener(e -> {
            user.setAuthMode((AuthMode) modeDropdown.getSelectedItem());
            persistenceManager.commitState();
            updateCardVisibility.run();
        });

        updateCardVisibility.run();

        // Preset action listener
        presetBox.addActionListener(e -> {
            int idx = presetBox.getSelectedIndex();
            if (idx == 1) { // Bearer JWT
                modeDropdown.setSelectedItem(AuthMode.STATIC);
                headersArea.setText("Authorization: Bearer <paste_token_here>");
            } else if (idx == 2) { // Cookie session
                modeDropdown.setSelectedItem(AuthMode.STATIC);
                headersArea.setText("Cookie: session=xyz123; XSRF-TOKEN=csrf456\nX-XSRF-TOKEN: csrf456");
            } else if (idx == 3) { // OAuth2 Refresh
                modeDropdown.setSelectedItem(AuthMode.OAUTH2_REFRESH);
                tokenEndpointField.setText("https://auth.example.com/oauth/v2/token");
                clientIdField.setText("burp_client_id");
                refreshTokenField.setText("<paste_refresh_token_here>");
            } else if (idx == 4) { // OAuth2 Client Creds
                modeDropdown.setSelectedItem(AuthMode.OAUTH2_CLIENT_CREDENTIALS);
                tokenEndpointField.setText("https://auth.example.com/oauth/v2/token");
                clientIdField.setText("service_client_id");
            } else if (idx == 5) { // DPoP
                modeDropdown.setSelectedItem(AuthMode.DPOP_OAUTH2);
                dpopCheck.setSelected(true);
                user.setDpopEnabled(true);
            } else if (idx == 6) { // API Key
                modeDropdown.setSelectedItem(AuthMode.STATIC);
                headersArea.setText("X-API-Key: <paste_api_key_here>");
            } else if (idx == 7) { // Macro login
                modeDropdown.setSelectedItem(AuthMode.CUSTOM_LOGIN);
                loginEndpointField.setText("https://api.example.com/api/v1/auth/login");
                loginBodyArea.setText("{\"email\": \"victim_user@target.com\", \"password\": \"SecretPass!\"}");
                extractPathField.setText("access_token");
                destHeaderField.setText("Authorization: Bearer ");
            }
        });

        // Diagnostics Button Handlers
        testHealthBtn.addActionListener(e -> {
            healthBadge.setText("● Probing session...");
            healthBadge.setForeground(Color.GRAY);

            Executors.newVirtualThreadPerTaskExecutor().submit(() -> {
                String fallbackUrl = getFallbackUrl();
                SessionHealthChecker.SessionHealthResult res = authBroker.getSessionHealthChecker().checkHealth(user, fallbackUrl);

                SwingUtilities.invokeLater(() -> {
                    healthBadge.setText("● " + res.getMessage());
                    if (res.getStatus() == SessionHealthChecker.HealthStatus.ACTIVE) {
                        healthBadge.setForeground(new Color(0, 140, 0));
                    } else if (res.getStatus() == SessionHealthChecker.HealthStatus.EXPIRED) {
                        healthBadge.setForeground(Color.RED);
                    } else if (res.getStatus() == SessionHealthChecker.HealthStatus.FORBIDDEN) {
                        healthBadge.setForeground(Color.MAGENTA);
                    } else {
                        healthBadge.setForeground(new Color(180, 100, 0));
                    }
                });
            });
        });

        refreshNowBtn.addActionListener(e -> {
            healthBadge.setText("● Executing re-auth flow...");
            healthBadge.setForeground(Color.BLUE);

            Executors.newVirtualThreadPerTaskExecutor().submit(() -> {
                boolean success = authBroker.retryWithRefreshedSession(user);
                SwingUtilities.invokeLater(() -> {
                    if (success) {
                        headersArea.setText(user.getHeadersText());
                        healthBadge.setText("● Refresh Succeeded! Probing liveness...");
                        healthBadge.setForeground(new Color(0, 140, 0));
                        testHealthBtn.doClick();
                    } else {
                        healthBadge.setText("● Refresh/Login Failed. Check logs.");
                        healthBadge.setForeground(Color.RED);
                    }
                });
            });
        });

        inspectJwtBtn.addActionListener(e -> {
            String jwt = JwtInspector.findFirstJwtInText(headersArea.getText());
            if (jwt == null) {
                JOptionPane.showMessageDialog(this,
                        "No JWT Bearer or DPoP token found in the current replacement headers text.",
                        "No JWT Detected", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "JWT Inspector & Decoded Claims", true);
            dialog.setLayout(new BorderLayout(8, 8));
            dialog.setSize(550, 450);
            dialog.setLocationRelativeTo(this);

            JPanel infoTop = new JPanel(new GridLayout(4, 1, 4, 4));
            infoTop.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
            infoTop.add(new JLabel("Subject (sub): " + (JwtInspector.getSubject(jwt) != null ? JwtInspector.getSubject(jwt) : "<None>")));
            infoTop.add(new JLabel("Issuer (iss): " + (JwtInspector.getIssuer(jwt) != null ? JwtInspector.getIssuer(jwt) : "<None>")));
            infoTop.add(new JLabel("Status: " + JwtInspector.getFormattedRemainingTime(jwt)));
            infoTop.add(new JLabel("Decoded Payload JSON:"));

            JTextArea claimsArea = new JTextArea(JwtInspector.getDecodedClaimsPretty(jwt));
            claimsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            claimsArea.setEditable(false);

            dialog.add(infoTop, BorderLayout.NORTH);
            dialog.add(new JScrollPane(claimsArea), BorderLayout.CENTER);

            JButton closeBtn = new JButton("Close");
            closeBtn.addActionListener(ev -> dialog.dispose());
            JPanel btm = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            btm.add(closeBtn);
            dialog.add(btm, BorderLayout.SOUTH);

            dialog.setVisible(true);
        });

        // Header fetch helpers
        fetchCookiesBtn.addActionListener(e -> {
            String cookie = extractHeaderValue("Cookie");
            if (cookie != null) appendOrReplaceHeader(headersArea, "Cookie", cookie);
            else showNoHeaderFound("Cookie");
        });

        fetchAuthBtn.addActionListener(e -> {
            String auth = extractHeaderValue("Authorization");
            if (auth != null) appendOrReplaceHeader(headersArea, "Authorization", auth);
            else showNoHeaderFound("Authorization");
        });

        fetchBothBtn.addActionListener(e -> {
            String cookie = extractHeaderValue("Cookie");
            String auth = extractHeaderValue("Authorization");
            boolean found = false;
            if (cookie != null) { appendOrReplaceHeader(headersArea, "Cookie", cookie); found = true; }
            if (auth != null) { appendOrReplaceHeader(headersArea, "Authorization", auth); found = true; }
            if (!found) showNoHeaderFound("Cookie or Authorization");
        });

        clearHeadersBtn.addActionListener(e -> headersArea.setText(""));

        return new JScrollPane(authContainer);
    }

    private String getFallbackUrl() {
        HttpRequestResponse tx = trafficSupplier != null ? trafficSupplier.get() : null;
        if (tx != null && tx.request() != null) {
            return tx.request().url();
        }
        return null;
    }

    private String extractHeaderValue(String headerName) {
        HttpRequestResponse tx = trafficSupplier != null ? trafficSupplier.get() : null;
        if (tx == null || tx.request() == null) return null;

        HttpRequest req = tx.request();
        for (HttpHeader h : req.headers()) {
            if (h.name().equalsIgnoreCase(headerName)) {
                return h.value();
            }
        }
        return null;
    }

    private void appendOrReplaceHeader(JTextArea area, String headerName, String headerValue) {
        String current = area.getText();
        String newLine = headerName + ": " + headerValue;
        if (current.isEmpty()) {
            area.setText(newLine);
            return;
        }

        String[] lines = current.split("\r?\n");
        StringBuilder sb = new StringBuilder();
        boolean replaced = false;

        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                sb.append(newLine).append("\n");
                replaced = true;
            } else if (!line.trim().isEmpty()) {
                sb.append(line).append("\n");
            }
        }

        if (!replaced) {
            sb.append(newLine).append("\n");
        }

        area.setText(sb.toString().trim());
    }

    private void showNoHeaderFound(String headerName) {
        JOptionPane.showMessageDialog(this,
                "No " + headerName + " header found in the currently selected or latest intercepted request.",
                "Header Not Found", JOptionPane.INFORMATION_MESSAGE);
    }

    private void promptAddUser() {
        int nextNum = persistenceManager.getUserProfiles().size() + 1;
        String defaultName = "User " + nextNum + " (Low Priv)";
        String name = (String) JOptionPane.showInputDialog(
                this,
                "Enter a descriptive name for the new user profile:",
                "Add User Profile",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                defaultName
        );

        if (name != null && !name.trim().isEmpty()) {
            UserProfile newUser = new UserProfile("user_" + nextNum + "_" + System.currentTimeMillis(), name.trim());
            persistenceManager.initDefaultUserDetectors(newUser);
            persistenceManager.getUserProfiles().add(newUser);
            persistenceManager.getUserTrafficStore(newUser.getId());
            persistenceManager.commitState();
            refreshTabs();
            userTabs.setSelectedIndex(userTabs.getTabCount() - 1);
            if (onStructureChanged != null) onStructureChanged.run();
        }
    }

    private void promptRenameUser() {
        int selected = userTabs.getSelectedIndex();
        if (selected < 0 || selected >= persistenceManager.getUserProfiles().size()) return;

        UserProfile current = persistenceManager.getUserProfiles().get(selected);
        String newName = (String) JOptionPane.showInputDialog(
                this,
                "Enter new name for profile '" + current.getName() + "':",
                "Rename User Profile",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                current.getName()
        );

        if (newName != null && !newName.trim().isEmpty()) {
            current.setName(newName.trim());
            persistenceManager.commitState();
            refreshTabs();
            if (onStructureChanged != null) onStructureChanged.run();
        }
    }

    private void duplicateSelectedUser() {
        int selected = userTabs.getSelectedIndex();
        if (selected < 0 || selected >= persistenceManager.getUserProfiles().size()) return;

        UserProfile src = persistenceManager.getUserProfiles().get(selected);
        int nextNum = persistenceManager.getUserProfiles().size() + 1;
        UserProfile copy = new UserProfile("user_" + nextNum + "_" + System.currentTimeMillis(), src.getName() + " (Copy)");

        copy.setAuthMode(src.getAuthMode());
        copy.setHeadersText(src.getHeadersText());
        copy.setTokenEndpoint(src.getTokenEndpoint());
        copy.setClientId(src.getClientId());
        copy.setClientSecret(src.getClientSecret());
        copy.setRefreshToken(src.getRefreshToken());
        copy.setDpopEnabled(src.isDpopEnabled());
        copy.setServerDPoPNonce(src.getServerDPoPNonce());
        copy.setLoginEndpoint(src.getLoginEndpoint());
        copy.setLoginMethod(src.getLoginMethod());
        copy.setLoginContentType(src.getLoginContentType());
        copy.setLoginRequestBody(src.getLoginRequestBody());
        copy.setTokenExtractionType(src.getTokenExtractionType());
        copy.setTokenExtractionPath(src.getTokenExtractionPath());
        copy.setTokenDestinationHeader(src.getTokenDestinationHeader());
        copy.setHealthCheckEndpoint(src.getHealthCheckEndpoint());
        copy.setHealthCheckExpectedStatus(src.getHealthCheckExpectedStatus());
        copy.setSyncCsrf(src.isSyncCsrf());
        copy.setCsrfCookieName(src.getCsrfCookieName());
        copy.setCsrfHeaderName(src.getCsrfHeaderName());
        copy.setDetectorAndLogic(src.isDetectorAndLogic());

        src.getEnforcementDetectors().forEach(d -> copy.getEnforcementDetectors().add(
                new EnforcementDetector(d.getType(), d.getContent())));
        src.getMatchReplaceRules().forEach(r -> copy.getMatchReplaceRules().add(
                new MatchReplaceRule(r.getType(), r.getMatch(), r.getReplace())));

        persistenceManager.getUserProfiles().add(copy);
        persistenceManager.getUserTrafficStore(copy.getId());
        persistenceManager.commitState();
        refreshTabs();
        userTabs.setSelectedIndex(userTabs.getTabCount() - 1);
        if (onStructureChanged != null) onStructureChanged.run();
    }

    private void promptRemoveUser() {
        int selected = userTabs.getSelectedIndex();
        if (selected < 0 || selected >= persistenceManager.getUserProfiles().size()) return;

        if (persistenceManager.getUserProfiles().size() <= 1) {
            JOptionPane.showMessageDialog(this,
                    "Cannot remove the only configured user profile.\nAutorize requires at least one user profile to replay requests.",
                    "Cannot Remove Profile", JOptionPane.WARNING_MESSAGE);
            return;
        }

        UserProfile user = persistenceManager.getUserProfiles().get(selected);
        int confirm = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to delete profile '" + user.getName() + "' and its traffic history?",
                "Remove User Profile",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (confirm == JOptionPane.YES_OPTION) {
            persistenceManager.getUserProfiles().remove(selected);
            persistenceManager.commitState();
            refreshTabs();
            if (onStructureChanged != null) onStructureChanged.run();
        }
    }

    private static class SimpleDocumentListener implements javax.swing.event.DocumentListener {
        private final Runnable onChange;
        SimpleDocumentListener(Runnable onChange) { this.onChange = onChange; }
        public void insertUpdate(javax.swing.event.DocumentEvent e) { onChange.run(); }
        public void removeUpdate(javax.swing.event.DocumentEvent e) { onChange.run(); }
        public void changedUpdate(javax.swing.event.DocumentEvent e) { onChange.run(); }
    }
}
