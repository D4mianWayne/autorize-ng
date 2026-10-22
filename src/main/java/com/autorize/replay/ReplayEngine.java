package com.autorize.replay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.autorize.auth.AuthBroker;
import com.autorize.diff.DiffEngine;
import com.autorize.diff.DiffResult;
import com.autorize.model.EnforcementStatus;
import com.autorize.model.LogEntry;
import com.autorize.model.MatchReplaceRule;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class ReplayEngine {

    private final MontoyaApi api;
    private final PersistenceManager persistenceManager;
    private final AuthBroker authBroker;
    private final DiffEngine diffEngine;
    private final SafetyGuard safetyGuard;
    private final ExecutorService executor;
    private final ObjectMapper objectMapper;

    private Consumer<LogEntry> onLogEntryAdded;
    private volatile HttpRequestResponse lastInterceptedTx;

    public HttpRequestResponse getLastInterceptedTx() {
        return lastInterceptedTx;
    }

    public ReplayEngine(MontoyaApi api, PersistenceManager persistenceManager, AuthBroker authBroker, DiffEngine diffEngine) {
        this.api = api;
        this.persistenceManager = persistenceManager;
        this.authBroker = authBroker;
        this.diffEngine = diffEngine;
        this.safetyGuard = new SafetyGuard(persistenceManager);
        this.objectMapper = new ObjectMapper();
        // Java 21 Virtual Threads Executor
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
    }

    public void setOnLogEntryAdded(Consumer<LogEntry> listener) {
        this.onLogEntryAdded = listener;
    }

    public void processInterceptedTransaction(HttpRequestResponse originalTx) {
        this.lastInterceptedTx = originalTx;
        HttpRequest origReq = originalTx.request();
        HttpResponse origRes = originalTx.response();

        if (origRes == null) return;

        // Check safety guard
        if (!safetyGuard.isSafeToReplay(origReq)) {
            api.logging().logToOutput("Autorize SafetyGuard: Skipped state-changing request " + origReq.method() + " " + origReq.url());
            return;
        }

        executor.submit(() -> executeReplay(originalTx));
    }

    private void executeReplay(HttpRequestResponse originalTx) {
        HttpRequest origReq = originalTx.request();
        HttpResponse origRes = originalTx.response();

        int origLen = origRes.body().length();
        int origTrafficIndex = persistenceManager.recordOriginalTraffic(originalTx);

        int logId = persistenceManager.getNextRequestId();
        LogEntry logEntry = new LogEntry(logId, origReq.method(), origReq.url(), origTrafficIndex, origLen);

        // 1. Unauthenticated Replay
        if (persistenceManager.isCheckUnauthenticated()) {
            try {
                HttpRequest unauthReq = authBroker.buildUnauthenticatedRequest(origReq, persistenceManager.getUserProfiles());
                HttpRequestResponse unauthTx = api.http().sendRequest(unauthReq);

                if (unauthTx != null && unauthTx.response() != null) {
                    int unauthTrafficIndex = persistenceManager.recordUnauthTraffic(unauthTx);
                    logEntry.setUnauthTrafficIndex(unauthTrafficIndex);
                    logEntry.setUnauthLength(unauthTx.response().body().length());

                    DiffResult diff = diffEngine.evaluateBypass(origRes, unauthTx.response(),
                            origReq.url(), origReq.bodyToString(),
                            persistenceManager.getUnauthDetectors(), false);

                    logEntry.setUnauthStatus(diff.getStatus());
                    logEntry.setUnauthDetails(diff.getDetails());
                } else {
                    logEntry.setUnauthStatus(EnforcementStatus.ERROR);
                }
            } catch (Exception e) {
                logEntry.setUnauthStatus(EnforcementStatus.ERROR);
                logEntry.setUnauthDetails("Error executing unauthenticated replay: " + e.getMessage());
            }
        } else {
            logEntry.setUnauthStatus(EnforcementStatus.DISABLED);
        }

        // 2. Multi-User Replays
        List<UserProfile> users = persistenceManager.getUserProfiles();
        for (UserProfile user : users) {
            try {
                HttpRequest userReq = applyMatchReplaceRules(origReq, user.getMatchReplaceRules());
                userReq = authBroker.applyAuthentication(userReq, user);

                HttpRequestResponse userTx = api.http().sendRequest(userReq);

                // Reactive 401 Handling: DPoP Nonce Challenge or Token Refresh / Macro Login
                if (userTx != null && userTx.response() != null && userTx.response().statusCode() == 401) {
                    boolean retried = false;

                    // 1. DPoP-Nonce Challenge (RFC 9449 Section 8)
                    String dpopNonce = userTx.response().headerValue("DPoP-Nonce");
                    if (dpopNonce != null && !dpopNonce.isBlank()) {
                        user.setServerDPoPNonce(dpopNonce.trim());
                        userReq = authBroker.applyAuthentication(origReq, user);
                        userReq = applyMatchReplaceRules(userReq, user.getMatchReplaceRules());
                        userTx = api.http().sendRequest(userReq);
                        retried = true;
                    }

                    // 2. Token Refresh or Macro Login Re-Auth
                    if (!retried || (userTx != null && userTx.response() != null && userTx.response().statusCode() == 401)) {
                        if (authBroker.retryWithRefreshedSession(user)) {
                            userReq = authBroker.applyAuthentication(origReq, user);
                            userReq = applyMatchReplaceRules(userReq, user.getMatchReplaceRules());
                            userTx = api.http().sendRequest(userReq);
                        }
                    }
                }

                if (userTx != null && userTx.response() != null) {
                    // Capture dynamic response headers (DPoP nonce, Anti-CSRF tokens, etc.)
                    authBroker.processReplayResponse(user, userTx.response());
                    int userTrafficIndex = persistenceManager.recordUserTraffic(user.getId(), userTx);
                    int userLen = userTx.response().body().length();

                    DiffResult diff = diffEngine.evaluateBypass(origRes, userTx.response(),
                            origReq.url(), origReq.bodyToString(),
                            user.getEnforcementDetectors(), user.isDetectorAndLogic());

                    LogEntry.UserResult userResult = new LogEntry.UserResult(
                            userTrafficIndex, userLen, diff.getStatus(), diff.getSimilarityScore(), diff.getDetails()
                    );
                    logEntry.addUserResult(user.getId(), userResult);
                } else {
                    logEntry.addUserResult(user.getId(), new LogEntry.UserResult(-1, 0, EnforcementStatus.ERROR, 0.0, "No response"));
                }
            } catch (Exception e) {
                logEntry.addUserResult(user.getId(), new LogEntry.UserResult(-1, 0, EnforcementStatus.ERROR, 0.0, e.getMessage()));
            }
        }

        // 3. Commit to project persistence & notify UI
        persistenceManager.appendLogEntry(logEntry);

        if (onLogEntryAdded != null) {
            SwingUtilities.invokeLater(() -> onLogEntryAdded.accept(logEntry));
        }
    }

    private HttpRequest applyMatchReplaceRules(HttpRequest request, List<MatchReplaceRule> rules) {
        HttpRequest req = request;
        if (rules == null || rules.isEmpty()) return req;

        for (MatchReplaceRule rule : rules) {
            if (!rule.isEnabled()) continue;
            try {
                switch (rule.getType()) {
                    case HEADER_STRING:
                        for (var h : req.headers()) {
                            if (h.toString().contains(rule.getMatch())) {
                                String replaced = h.value().replace(rule.getMatch(), rule.getReplace());
                                req = req.withRemovedHeader(h.name()).withAddedHeader(h.name(), replaced);
                            }
                        }
                        break;
                    case HEADER_REGEX:
                        for (var h : req.headers()) {
                            if (rule.getCompiledPattern().matcher(h.toString()).find()) {
                                String replaced = rule.getCompiledPattern().matcher(h.value()).replaceAll(rule.getReplace());
                                req = req.withRemovedHeader(h.name()).withAddedHeader(h.name(), replaced);
                            }
                        }
                        break;
                    case PATH_STRING:
                        String path = req.path();
                        if (path.contains(rule.getMatch())) {
                            req = req.withPath(path.replace(rule.getMatch(), rule.getReplace()));
                        }
                        break;
                    case PATH_REGEX:
                        String rPath = req.path();
                        if (rule.getCompiledPattern().matcher(rPath).find()) {
                            req = req.withPath(rule.getCompiledPattern().matcher(rPath).replaceAll(rule.getReplace()));
                        }
                        break;
                    case BODY_STRING:
                        String body = req.bodyToString();
                        if (body.contains(rule.getMatch())) {
                            req = req.withBody(body.replace(rule.getMatch(), rule.getReplace()));
                        }
                        break;
                    case BODY_REGEX:
                        String rBody = req.bodyToString();
                        if (rule.getCompiledPattern().matcher(rBody).find()) {
                            req = req.withBody(rule.getCompiledPattern().matcher(rBody).replaceAll(rule.getReplace()));
                        }
                        break;
                    case QUERY_PARAM_STRING:
                        String pathStr = req.path();
                        String match = rule.getMatch();
                        String replace = rule.getReplace();
                        if (match.contains("=")) {
                            if (pathStr.contains(match)) {
                                req = req.withPath(pathStr.replace(match, replace));
                            }
                        } else {
                            var p = java.util.regex.Pattern.compile("([?&])" + java.util.regex.Pattern.quote(match) + "=[^&]*");
                            var m = p.matcher(pathStr);
                            if (m.find()) {
                                req = req.withPath(m.replaceAll("$1" + java.util.regex.Matcher.quoteReplacement(match + "=" + replace)));
                            }
                        }
                        break;
                    case QUERY_PARAM_REGEX:
                        String qPath = req.path();
                        if (rule.getCompiledPattern().matcher(qPath).find()) {
                            req = req.withPath(rule.getCompiledPattern().matcher(qPath).replaceAll(rule.getReplace()));
                        }
                        break;
                    case JSON_FIELD:
                        String jsonBody = req.bodyToString();
                        if (jsonBody != null && !jsonBody.isBlank() && (jsonBody.startsWith("{") || jsonBody.startsWith("["))) {
                            try {
                                JsonNode root = objectMapper.readTree(jsonBody);
                                boolean modified = replaceJsonFieldRecursive(root, rule.getMatch(), rule.getReplace());
                                if (modified) {
                                    req = req.withBody(objectMapper.writeValueAsString(root));
                                }
                            } catch (Exception ignored) {}
                        }
                        break;
                    default:
                        break;
                }
            } catch (Exception ignored) {}
        }
        return req;
    }

    private boolean replaceJsonFieldRecursive(JsonNode node, String targetKey, String replacementValue) {
        if (node == null) return false;
        boolean changed = false;

        if (targetKey.contains(".")) {
            String[] parts = targetKey.split("\\.", 2);
            String head = parts[0];
            String tail = parts[1];
            if (node.isObject() && node.has(head)) {
                return replaceJsonFieldRecursive(node.get(head), tail, replacementValue);
            }
            return false;
        }

        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            List<String> toReplace = new ArrayList<>();
            var it = obj.fieldNames();
            while (it.hasNext()) {
                String field = it.next();
                if (field.equalsIgnoreCase(targetKey)) {
                    toReplace.add(field);
                }
            }
            for (String field : toReplace) {
                obj.set(field, parseReplacementJsonNode(replacementValue));
                changed = true;
            }

            var fieldsIt = obj.fields();
            while (fieldsIt.hasNext()) {
                var entry = fieldsIt.next();
                if (replaceJsonFieldRecursive(entry.getValue(), targetKey, replacementValue)) {
                    changed = true;
                }
            }
        } else if (node.isArray()) {
            ArrayNode arr = (ArrayNode) node;
            for (JsonNode item : arr) {
                if (replaceJsonFieldRecursive(item, targetKey, replacementValue)) {
                    changed = true;
                }
            }
        }
        return changed;
    }

    private JsonNode parseReplacementJsonNode(String val) {
        if (val == null || val.equalsIgnoreCase("null")) {
            return NullNode.getInstance();
        }
        if (val.equalsIgnoreCase("true") || val.equalsIgnoreCase("false")) {
            return BooleanNode.valueOf(Boolean.parseBoolean(val));
        }
        try {
            long l = Long.parseLong(val);
            return new LongNode(l);
        } catch (NumberFormatException ignored) {}
        try {
            double d = Double.parseDouble(val);
            return new DoubleNode(d);
        } catch (NumberFormatException ignored) {}
        if ((val.startsWith("{") && val.endsWith("}")) || (val.startsWith("[") && val.endsWith("]"))) {
            try {
                return objectMapper.readTree(val);
            } catch (Exception ignored) {}
        }
        return new TextNode(val);
    }

    public void retest(LogEntry entry) {
        HttpRequestResponse origTx = persistenceManager.getOriginalTraffic(entry.getOrigTrafficIndex());
        if (origTx != null) {
            executor.submit(() -> executeReplay(origTx));
        }
    }

    public void retestAll() {
        for (LogEntry entry : persistenceManager.getLogEntries()) {
            retest(entry);
        }
    }

    public void shutdown() {
        executor.shutdown();
    }
}
