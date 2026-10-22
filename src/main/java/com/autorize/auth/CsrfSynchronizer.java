package com.autorize.auth;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.autorize.model.UserProfile;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CsrfSynchronizer {

    private final Map<String, String> userCsrfTokens = new ConcurrentHashMap<>();

    public void recordCsrfToken(String userId, String token) {
        if (token != null && !token.isBlank()) {
            userCsrfTokens.put(userId, token.trim());
        }
    }

    public String getCsrfToken(String userId) {
        return userCsrfTokens.get(userId);
    }

    public void captureCsrfFromResponse(String userId, HttpResponse response, UserProfile user) {
        if (response == null || !user.isSyncCsrf()) return;

        // 1. Check custom CSRF Header in response
        String headerName = user.getCsrfHeaderName() != null ? user.getCsrfHeaderName() : "X-XSRF-TOKEN";
        String tokenFromHeader = response.headerValue(headerName);
        if (tokenFromHeader != null && !tokenFromHeader.isBlank()) {
            recordCsrfToken(userId, tokenFromHeader);
            return;
        }

        // Check common alternative header names
        for (String alt : new String[]{"X-CSRF-Token", "X-XSRF-TOKEN", "CSRF-Token", "anti-csrf"}) {
            String val = response.headerValue(alt);
            if (val != null && !val.isBlank()) {
                recordCsrfToken(userId, val);
                return;
            }
        }

        // 2. Check Set-Cookie headers
        String targetCookie = (user.getCsrfCookieName() != null ? user.getCsrfCookieName() : "XSRF-TOKEN").toLowerCase() + "=";
        for (HttpHeader h : response.headers()) {
            if (h.name().equalsIgnoreCase("Set-Cookie")) {
                String cookie = h.value();
                int semi = cookie.indexOf(';');
                String pair = (semi != -1 ? cookie.substring(0, semi) : cookie).trim();
                if (pair.toLowerCase().startsWith(targetCookie)) {
                    String token = pair.substring(targetCookie.length()).trim();
                    recordCsrfToken(userId, token);
                    return;
                }
            }
        }
    }

    public HttpRequest applyCsrfHeader(HttpRequest request, UserProfile user) {
        if (!user.isSyncCsrf()) return request;

        String token = userCsrfTokens.get(user.getId());
        if (token == null || token.isBlank()) {
            token = extractTokenFromUserHeaders(user);
        }

        if (token != null && !token.isBlank()) {
            String headerName = user.getCsrfHeaderName();
            if (headerName != null && !headerName.isBlank()) {
                request = request.withRemovedHeader(headerName)
                        .withAddedHeader(headerName, token);
            }
        }
        return request;
    }

    private String extractTokenFromUserHeaders(UserProfile user) {
        String cookieName = (user.getCsrfCookieName() != null ? user.getCsrfCookieName() : "XSRF-TOKEN").toLowerCase() + "=";
        String headers = user.getHeadersText() != null ? user.getHeadersText() : "";
        for (String line : headers.split("\n")) {
            if (line.toLowerCase().startsWith("cookie:")) {
                String cookieVal = line.substring(7);
                for (String part : cookieVal.split(";")) {
                    String p = part.trim();
                    if (p.toLowerCase().startsWith(cookieName)) {
                        return p.substring(cookieName.length()).trim();
                    }
                }
            }
        }
        return null;
    }
}
