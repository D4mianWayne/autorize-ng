package com.autorize;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.autorize.auth.AuthBroker;
import com.autorize.diff.DiffEngine;
import com.autorize.filter.FilterPipeline;
import com.autorize.persistence.PersistenceManager;
import com.autorize.replay.ReplayEngine;
import com.autorize.ui.MainTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class AutorizeExtension implements BurpExtension {

    private MontoyaApi api;
    private PersistenceManager persistenceManager;
    private AuthBroker authBroker;
    private DiffEngine diffEngine;
    private FilterPipeline filterPipeline;
    private ReplayEngine replayEngine;
    private MainTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Autorize Next-Gen");

        // 1. Initialize Persistence Manager & Hydrate from Project File
        this.persistenceManager = new PersistenceManager(api);
        this.persistenceManager.hydrateFromProject();

        // 2. Initialize Core Subsystems
        this.authBroker = new AuthBroker(api, persistenceManager);
        this.diffEngine = new DiffEngine();
        this.filterPipeline = new FilterPipeline(api, persistenceManager);
        this.replayEngine = new ReplayEngine(api, persistenceManager, authBroker, diffEngine);

        // 3. Register HTTP Handler
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                if (persistenceManager.isInterceptEnabled() && persistenceManager.isPrevent304()) {
                    var modified = filterPipeline.apply304Prevention(requestToBeSent);
                    return RequestToBeSentAction.continueWith(modified);
                }
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                if (filterPipeline.shouldProcess(responseReceived.initiatingRequest(), responseReceived, responseReceived.toolSource())) {
                    HttpRequestResponse tx = HttpRequestResponse.httpRequestResponse(responseReceived.initiatingRequest(), responseReceived);
                    replayEngine.processInterceptedTransaction(tx);
                }
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        // 4. Register Context Menu Provider
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> items = new ArrayList<>();
                var messages = event.selectedRequestResponses();
                if (messages != null && !messages.isEmpty()) {
                    JMenuItem sendItem = new JMenuItem("Send to Autorize Next-Gen");
                    sendItem.addActionListener(e -> {
                        for (var msg : messages) {
                            if (msg.response() != null) {
                                replayEngine.processInterceptedTransaction(msg);
                            }
                        }
                    });
                    items.add(sendItem);

                    var firstMsg = messages.get(0);
                    if (firstMsg.request() != null) {
                        List<com.autorize.model.UserProfile> users = persistenceManager.getUserProfiles();
                        if (!users.isEmpty()) {
                            // Cookie sender
                            String cookie = firstMsg.request().headerValue("Cookie");
                            if (cookie != null && !cookie.isBlank()) {
                                if (users.size() == 1) {
                                    var user = users.get(0);
                                    JMenuItem cookieItem = new JMenuItem("Send Cookie to Autorize (" + user.getName() + ")");
                                    cookieItem.addActionListener(e -> updateUserHeader(user, "Cookie", cookie));
                                    items.add(cookieItem);
                                } else {
                                    JMenu cookieMenu = new JMenu("Send Cookie to Autorize");
                                    for (var user : users) {
                                        JMenuItem userItem = new JMenuItem(user.getName());
                                        userItem.addActionListener(e -> updateUserHeader(user, "Cookie", cookie));
                                        cookieMenu.add(userItem);
                                    }
                                    items.add(cookieMenu);
                                }
                            }

                            // Authorization sender
                            String auth = firstMsg.request().headerValue("Authorization");
                            if (auth != null && !auth.isBlank()) {
                                if (users.size() == 1) {
                                    var user = users.get(0);
                                    JMenuItem authItem = new JMenuItem("Send Authorization to Autorize (" + user.getName() + ")");
                                    authItem.addActionListener(e -> updateUserHeader(user, "Authorization", auth));
                                    items.add(authItem);
                                } else {
                                    JMenu authMenu = new JMenu("Send Authorization to Autorize");
                                    for (var user : users) {
                                        JMenuItem userItem = new JMenuItem(user.getName());
                                        userItem.addActionListener(e -> updateUserHeader(user, "Authorization", auth));
                                        authMenu.add(userItem);
                                    }
                                    items.add(authMenu);
                                }
                            }
                        }
                    }
                }
                return items;
            }
        });

        // 5. Build and Register UI Suite Tab
        SwingUtilities.invokeLater(() -> {
            mainTab = new MainTab(api, persistenceManager, replayEngine, authBroker);
            api.userInterface().registerSuiteTab("Autorize", mainTab);
        });

        // 6. Register Unload Hook
        api.extension().registerUnloadingHandler(() -> {
            replayEngine.shutdown();
            persistenceManager.commitState();
            api.logging().logToOutput("Autorize Next-Gen unloaded successfully.");
        });

        api.logging().logToOutput("""
                ================================================================
                Autorize Next-Gen (v2.0.0) Loaded Successfully!
                - Platform: Burp Suite Montoya API (Pure Java 21)
                - Persistence: Burp Project File (.burp) Native Storage
                - Features: Dynamic OAuth2, DPoP, Semantic JSON/GraphQL Diffing
                ================================================================
                """);
    }

    private void updateUserHeader(com.autorize.model.UserProfile user, String headerName, String headerValue) {
        String current = user.getHeadersText() != null ? user.getHeadersText() : "";
        StringBuilder sb = new StringBuilder();
        boolean replaced = false;
        for (String line : current.split("\n")) {
            if (line.trim().toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                sb.append(headerName).append(": ").append(headerValue).append("\n");
                replaced = true;
            } else if (!line.trim().isEmpty()) {
                sb.append(line).append("\n");
            }
        }
        if (!replaced) {
            sb.append(headerName).append(": ").append(headerValue).append("\n");
        }
        user.setHeadersText(sb.toString().trim());
        persistenceManager.commitState();
        api.logging().logToOutput("Autorize Next-Gen: Updated " + headerName + " for " + user.getName());
    }
}
