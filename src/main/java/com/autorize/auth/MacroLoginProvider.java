package com.autorize.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class MacroLoginProvider {

    private final MontoyaApi api;
    private final PersistenceManager persistenceManager;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public MacroLoginProvider(MontoyaApi api, PersistenceManager persistenceManager) {
        this.api = api;
        this.persistenceManager = persistenceManager;
    }

    public synchronized boolean executeLogin(UserProfile user) {
        String endpoint = user.getLoginEndpoint();
        String body = user.getLoginRequestBody();
        String method = user.getLoginMethod() != null ? user.getLoginMethod().toUpperCase() : "POST";
        String contentType = user.getLoginContentType() != null ? user.getLoginContentType() : "application/json";

        if (endpoint == null || endpoint.isBlank()) {
            return false;
        }

        try {
            HttpRequest loginReq = HttpRequest.httpRequestFromUrl(endpoint)
                    .withMethod(method)
                    .withHeader("Content-Type", contentType)
                    .withHeader("Accept", "application/json, text/plain, */*")
                    .withBody(body != null ? body : "");

            HttpRequestResponse response = api.http().sendRequest(loginReq);
            if (response == null || response.response() == null) {
                api.logging().logToError("[-] Macro login for " + user.getName() + " received no response.");
                return false;
            }

            int statusCode = response.response().statusCode();
            if (statusCode < 200 || statusCode >= 300) {
                api.logging().logToError("[-] Macro login for " + user.getName() + " failed with HTTP " + statusCode +
                        "\nResponse: " + response.response().bodyToString());
                return false;
            }

            String extractType = user.getTokenExtractionType() != null ? user.getTokenExtractionType() : "JSON_FIELD";
            String extractPath = user.getTokenExtractionPath() != null ? user.getTokenExtractionPath().trim() : "access_token";
            String destinationHeader = user.getTokenDestinationHeader() != null ? user.getTokenDestinationHeader().trim() : "Authorization: Bearer ";

            boolean tokenExtracted = false;

            if ("SET_COOKIE".equalsIgnoreCase(extractType)) {
                // Extract cookies from Set-Cookie headers
                List<String> cookies = new ArrayList<>();
                for (HttpHeader h : response.response().headers()) {
                    if (h.name().equalsIgnoreCase("Set-Cookie")) {
                        String cookieVal = h.value();
                        int semi = cookieVal.indexOf(';');
                        String pair = (semi != -1 ? cookieVal.substring(0, semi) : cookieVal).trim();
                        if (!extractPath.isEmpty() && !extractPath.equals("*")) {
                            if (pair.toLowerCase().startsWith(extractPath.toLowerCase() + "=")) {
                                cookies.add(pair);
                            }
                        } else {
                            cookies.add(pair);
                        }
                    }
                }

                if (!cookies.isEmpty()) {
                    String fullCookieString = String.join("; ", cookies);
                    updateOrReplaceHeader(user, "Cookie", fullCookieString);
                    tokenExtracted = true;
                }
            } else if ("HEADER".equalsIgnoreCase(extractType)) {
                // Extract a specific header from response
                String headerVal = response.response().headerValue(extractPath);
                if (headerVal != null && !headerVal.isBlank()) {
                    int colon = destinationHeader.indexOf(':');
                    String destName = colon != -1 ? destinationHeader.substring(0, colon).trim() : "Authorization";
                    String destPrefix = colon != -1 ? destinationHeader.substring(colon + 1).trim() : "";
                    String fullVal = destPrefix.isEmpty() ? headerVal.trim() : destPrefix + " " + headerVal.trim();
                    updateOrReplaceHeader(user, destName, fullVal);
                    tokenExtracted = true;
                }
            } else {
                // JSON_FIELD (default)
                String resBody = response.response().bodyToString();
                JsonNode root = objectMapper.readTree(resBody);
                String token = extractJsonField(root, extractPath);

                if (token != null && !token.isBlank()) {
                    int colon = destinationHeader.indexOf(':');
                    String destName = colon != -1 ? destinationHeader.substring(0, colon).trim() : "Authorization";
                    String destPrefix = colon != -1 ? destinationHeader.substring(colon + 1).trim() : "Bearer";
                    String fullVal = destPrefix.isEmpty() ? token.trim() : destPrefix + " " + token.trim();

                    updateOrReplaceHeader(user, destName, fullVal);

                    // If token is JWT, record expiration
                    if (JwtInspector.isJwt(token)) {
                        Long exp = JwtInspector.getExpirationEpochSeconds(token);
                        if (exp != null) {
                            user.setAccessTokenExpiresAtEpochMs(exp * 1000);
                        }
                    } else {
                        // Default 1 hour freshness
                        user.setAccessTokenExpiresAtEpochMs(Instant.now().toEpochMilli() + 3600_000);
                    }
                    user.setCurrentAccessToken(token);
                    tokenExtracted = true;
                }
            }

            if (tokenExtracted) {
                persistenceManager.commitState();
                api.logging().logToOutput("[+] Macro login succeeded for " + user.getName() + " - session updated.");
                return true;
            } else {
                api.logging().logToError("[-] Macro login for " + user.getName() + ": could not extract token matching " + extractPath);
            }
        } catch (Exception e) {
            api.logging().logToError("[-] Macro login exception for " + user.getName() + ": " + e.getMessage());
        }
        return false;
    }

    private String extractJsonField(JsonNode root, String path) {
        if (root == null || path == null) return null;
        String[] parts = path.split("\\.");
        JsonNode current = root;

        for (String part : parts) {
            if (current == null || !current.has(part)) {
                return null;
            }
            current = current.get(part);
        }

        return (current != null && current.isValueNode()) ? current.asText() : null;
    }

    private void updateOrReplaceHeader(UserProfile user, String headerName, String headerValue) {
        String existing = user.getHeadersText() != null ? user.getHeadersText() : "";
        StringBuilder sb = new StringBuilder();
        boolean replaced = false;

        for (String line : existing.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                sb.append(headerName).append(": ").append(headerValue).append("\n");
                replaced = true;
            } else if (!trimmed.isEmpty()) {
                sb.append(trimmed).append("\n");
            }
        }

        if (!replaced) {
            sb.append(headerName).append(": ").append(headerValue).append("\n");
        }

        user.setHeadersText(sb.toString().trim());
    }
}
