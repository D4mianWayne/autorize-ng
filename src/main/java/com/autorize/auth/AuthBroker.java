package com.autorize.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.autorize.model.AuthMode;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class AuthBroker {

    private final MontoyaApi api;
    private final PersistenceManager persistenceManager;
    private final OAuth2RefreshProvider oauth2Provider;
    private final MacroLoginProvider macroLoginProvider;
    private final CsrfSynchronizer csrfSynchronizer;
    private final SessionHealthChecker sessionHealthChecker;
    private final Map<String, DPoPSigner> dpopSigners = new ConcurrentHashMap<>();

    public AuthBroker(MontoyaApi api, PersistenceManager persistenceManager) {
        this.api = api;
        this.persistenceManager = persistenceManager;
        this.oauth2Provider = new OAuth2RefreshProvider(api, persistenceManager);
        this.macroLoginProvider = new MacroLoginProvider(api, persistenceManager);
        this.csrfSynchronizer = new CsrfSynchronizer();
        this.sessionHealthChecker = new SessionHealthChecker(api, this);
    }

    public CsrfSynchronizer getCsrfSynchronizer() {
        return csrfSynchronizer;
    }

    public OAuth2RefreshProvider getOAuth2Provider() {
        return oauth2Provider;
    }

    public MacroLoginProvider getMacroLoginProvider() {
        return macroLoginProvider;
    }

    public SessionHealthChecker getSessionHealthChecker() {
        return sessionHealthChecker;
    }

    public HttpRequest applyAuthentication(HttpRequest originalRequest, UserProfile user) {
        // Step 1: Pre-emptive freshness check
        ensureTokenFreshness(user);

        // Step 2: Strip existing headers that conflict with user's replacement headers
        HttpRequest modifiedRequest = stripConflictingHeaders(originalRequest, user.getHeadersText());

        // Step 3: Inject user replacement headers
        String headersText = user.getHeadersText() != null ? user.getHeadersText() : "";
        String activeAccessToken = null;

        for (String line : headersText.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            int colonIndex = trimmed.indexOf(':');
            if (colonIndex > 0) {
                String headerName = trimmed.substring(0, colonIndex).trim();
                String headerValue = trimmed.substring(colonIndex + 1).trim();

                if (headerName.equalsIgnoreCase("Authorization")) {
                    activeAccessToken = JwtInspector.cleanToken(headerValue);
                }
                modifiedRequest = modifiedRequest.withAddedHeader(headerName, headerValue);
            }
        }

        // Step 4: Handle RFC 9449 DPoP proof generation
        if (user.isDpopEnabled() || user.getAuthMode() == AuthMode.DPOP_OAUTH2) {
            DPoPSigner signer = dpopSigners.computeIfAbsent(user.getId(), id -> new DPoPSigner());
            String proof = signer.generateProof(
                    originalRequest.method(),
                    originalRequest.url(),
                    user.getServerDPoPNonce(),
                    activeAccessToken
            );
            if (!proof.isEmpty()) {
                modifiedRequest = modifiedRequest.withRemovedHeader("DPoP")
                        .withAddedHeader("DPoP", proof);
            }
        }

        // Step 5: Synchronize CSRF token for state-changing methods
        modifiedRequest = csrfSynchronizer.applyCsrfHeader(modifiedRequest, user);

        return modifiedRequest;
    }

    public void processReplayResponse(UserProfile user, HttpResponse response) {
        if (response == null) return;

        // Capture DPoP-Nonce
        String dpopNonce = response.headerValue("DPoP-Nonce");
        if (dpopNonce != null && !dpopNonce.isBlank()) {
            user.setServerDPoPNonce(dpopNonce.trim());
        }

        // Capture Anti-CSRF tokens
        csrfSynchronizer.captureCsrfFromResponse(user.getId(), response, user);
    }

    public boolean retryWithRefreshedSession(UserProfile user) {
        AuthMode mode = user.getAuthMode();
        if (mode == AuthMode.OAUTH2_REFRESH || mode == AuthMode.OAUTH2_CLIENT_CREDENTIALS || mode == AuthMode.DPOP_OAUTH2) {
            return oauth2Provider.refreshAccessToken(user);
        } else if (mode == AuthMode.CUSTOM_LOGIN) {
            return macroLoginProvider.executeLogin(user);
        }
        return false;
    }

    public HttpRequest buildUnauthenticatedRequest(HttpRequest originalRequest, List<UserProfile> allUsers) {
        HttpRequest unauthRequest = originalRequest;

        Set<String> headersToStrip = new HashSet<>();
        headersToStrip.add("cookie");
        headersToStrip.add("authorization");
        headersToStrip.add("dpop");
        headersToStrip.add("x-api-key");
        headersToStrip.add("x-auth-token");
        headersToStrip.add("x-xsrf-token");
        headersToStrip.add("x-csrf-token");

        for (UserProfile user : allUsers) {
            if (user.getHeadersText() == null) continue;
            for (String line : user.getHeadersText().split("\n")) {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    headersToStrip.add(line.substring(0, colon).trim().toLowerCase());
                }
            }
        }

        for (HttpHeader header : originalRequest.headers()) {
            if (headersToStrip.contains(header.name().toLowerCase())) {
                unauthRequest = unauthRequest.withRemovedHeader(header.name());
            }
        }

        return unauthRequest;
    }

    private void ensureTokenFreshness(UserProfile user) {
        AuthMode mode = user.getAuthMode();
        boolean needsRefresh = false;

        if (mode == AuthMode.OAUTH2_REFRESH || mode == AuthMode.OAUTH2_CLIENT_CREDENTIALS || mode == AuthMode.DPOP_OAUTH2) {
            if (user.getAccessTokenExpiresAtEpochMs() > 0) {
                long now = Instant.now().toEpochMilli();
                if ((now + 60_000) >= user.getAccessTokenExpiresAtEpochMs()) {
                    needsRefresh = true;
                }
            }

            String authHeader = extractAuthorizationHeader(user.getHeadersText());
            if (authHeader != null && JwtInspector.isJwt(authHeader)) {
                if (JwtInspector.isExpired(authHeader, 60)) {
                    needsRefresh = true;
                }
            }

            if (needsRefresh) {
                oauth2Provider.refreshAccessToken(user);
            }
        } else if (mode == AuthMode.CUSTOM_LOGIN) {
            if (user.getAccessTokenExpiresAtEpochMs() > 0) {
                long now = Instant.now().toEpochMilli();
                if ((now + 60_000) >= user.getAccessTokenExpiresAtEpochMs()) {
                    macroLoginProvider.executeLogin(user);
                }
            }
        }
    }

    private HttpRequest stripConflictingHeaders(HttpRequest request, String replacementHeadersText) {
        if (replacementHeadersText == null) return request;
        HttpRequest req = request;
        Set<String> replacementNames = new HashSet<>();

        for (String line : replacementHeadersText.split("\n")) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                replacementNames.add(line.substring(0, colon).trim().toLowerCase());
            }
        }

        for (HttpHeader h : request.headers()) {
            if (replacementNames.contains(h.name().toLowerCase())) {
                req = req.withRemovedHeader(h.name());
            }
        }
        return req;
    }

    private String extractAuthorizationHeader(String headersText) {
        if (headersText == null) return null;
        for (String line : headersText.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.toLowerCase().startsWith("authorization:")) {
                return trimmed.substring(14).trim();
            }
        }
        return null;
    }
}
