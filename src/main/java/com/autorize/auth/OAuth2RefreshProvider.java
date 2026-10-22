package com.autorize.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.autorize.model.AuthMode;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

public class OAuth2RefreshProvider {

    private final MontoyaApi api;
    private final PersistenceManager persistenceManager;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public OAuth2RefreshProvider(MontoyaApi api, PersistenceManager persistenceManager) {
        this.api = api;
        this.persistenceManager = persistenceManager;
    }

    public synchronized boolean refreshAccessToken(UserProfile user) {
        String tokenEndpoint = user.getTokenEndpoint();
        String clientId = user.getClientId();
        String clientSecret = user.getClientSecret();
        String refreshToken = user.getRefreshToken();
        boolean isClientCreds = (user.getAuthMode() == AuthMode.OAUTH2_CLIENT_CREDENTIALS);

        if (tokenEndpoint == null || tokenEndpoint.isBlank()) {
            return false;
        }

        if (!isClientCreds && (refreshToken == null || refreshToken.isBlank())) {
            return false;
        }

        try {
            StringBuilder body = new StringBuilder();
            if (isClientCreds) {
                body.append("grant_type=client_credentials");
            } else {
                body.append("grant_type=refresh_token");
                body.append("&refresh_token=").append(URLEncoder.encode(refreshToken, StandardCharsets.UTF_8));
            }

            HttpRequest tokenRequest = HttpRequest.httpRequestFromUrl(tokenEndpoint)
                    .withMethod("POST")
                    .withHeader("Content-Type", "application/x-www-form-urlencoded")
                    .withHeader("Accept", "application/json");

            // Client authentication: prefer HTTP Basic Auth if secret present
            if (clientId != null && !clientId.isBlank() && clientSecret != null && !clientSecret.isBlank()) {
                String creds = clientId.trim() + ":" + clientSecret.trim();
                String basicAuth = Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8));
                tokenRequest = tokenRequest.withHeader("Authorization", "Basic " + basicAuth);
            } else if (clientId != null && !clientId.isBlank()) {
                body.append("&client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8));
            }

            tokenRequest = tokenRequest.withBody(body.toString());

            HttpRequestResponse response = api.http().sendRequest(tokenRequest);
            if (response != null && response.response() != null) {
                // Capture DPoP-Nonce if server issued one
                String dpopNonce = response.response().headerValue("DPoP-Nonce");
                if (dpopNonce != null && !dpopNonce.isBlank()) {
                    user.setServerDPoPNonce(dpopNonce.trim());
                }

                if (response.response().statusCode() == 200) {
                    String responseBody = response.response().bodyToString();
                    JsonNode json = objectMapper.readTree(responseBody);

                    if (json.has("access_token")) {
                        String newAccessToken = json.get("access_token").asText();
                        user.setCurrentAccessToken(newAccessToken);

                        // Handle refresh token rotation
                        if (json.has("refresh_token")) {
                            user.setRefreshToken(json.get("refresh_token").asText());
                        }

                        long expiresIn = json.has("expires_in") ? json.get("expires_in").asLong() : 3600;
                        user.setAccessTokenExpiresAtEpochMs(Instant.now().toEpochMilli() + (expiresIn * 1000));

                        // Update headers text to reflect new token
                        String tokenPrefix = (user.isDpopEnabled() || user.getAuthMode() == AuthMode.DPOP_OAUTH2) ? "DPoP " : "Bearer ";
                        updateHeadersWithNewToken(user, tokenPrefix, newAccessToken);

                        persistenceManager.commitState();
                        api.logging().logToOutput("[+] Successfully refreshed OAuth2 token for user: " + user.getName());
                        return true;
                    }
                } else {
                    int code = response.response().statusCode();
                    api.logging().logToError("[-] OAuth2 token request failed for " + user.getName() + ", status: " + code +
                            "\nResponse: " + response.response().bodyToString());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[-] OAuth2 refresh exception for " + user.getName() + ": " + e.getMessage());
        }
        return false;
    }

    private void updateHeadersWithNewToken(UserProfile user, String prefix, String newAccessToken) {
        String existingHeaders = user.getHeadersText() != null ? user.getHeadersText() : "";
        StringBuilder updated = new StringBuilder();
        boolean replaced = false;

        for (String line : existingHeaders.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.toLowerCase().startsWith("authorization:")) {
                updated.append("Authorization: ").append(prefix).append(newAccessToken).append("\n");
                replaced = true;
            } else if (!trimmed.isEmpty()) {
                updated.append(trimmed).append("\n");
            }
        }

        if (!replaced) {
            updated.append("Authorization: ").append(prefix).append(newAccessToken).append("\n");
        }

        user.setHeadersText(updated.toString().trim());
    }
}
