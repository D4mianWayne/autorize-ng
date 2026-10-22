package com.autorize.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.autorize.model.UserProfile;

public class SessionHealthChecker {

    public enum HealthStatus {
        ACTIVE,
        EXPIRED,
        FORBIDDEN,
        SERVER_ERROR,
        UNREACHABLE,
        UNCONFIGURED
    }

    public static class SessionHealthResult {
        private final HealthStatus status;
        private final int statusCode;
        private final long latencyMs;
        private final String message;
        private final String jwtDetails;

        public SessionHealthResult(HealthStatus status, int statusCode, long latencyMs, String message, String jwtDetails) {
            this.status = status;
            this.statusCode = statusCode;
            this.latencyMs = latencyMs;
            this.message = message;
            this.jwtDetails = jwtDetails;
        }

        public HealthStatus getStatus() { return status; }
        public int getStatusCode() { return statusCode; }
        public long getLatencyMs() { return latencyMs; }
        public String getMessage() { return message; }
        public String getJwtDetails() { return jwtDetails; }

        public static SessionHealthResult unconfigured() {
            return new SessionHealthResult(HealthStatus.UNCONFIGURED, 0, 0, "No health check endpoint configured.", "");
        }
    }

    private final MontoyaApi api;
    private final AuthBroker authBroker;

    public SessionHealthChecker(MontoyaApi api, AuthBroker authBroker) {
        this.api = api;
        this.authBroker = authBroker;
    }

    public SessionHealthResult checkHealth(UserProfile user, String fallbackUrl) {
        String targetUrl = user.getHealthCheckEndpoint();
        if (targetUrl == null || targetUrl.isBlank()) {
            targetUrl = fallbackUrl;
        }

        String jwtInHeaders = JwtInspector.findFirstJwtInText(user.getHeadersText());
        String jwtInfo = jwtInHeaders != null ? " | " + JwtInspector.getFormattedRemainingTime(jwtInHeaders) : "";

        if (targetUrl == null || targetUrl.isBlank()) {
            if (jwtInHeaders != null) {
                boolean expired = JwtInspector.isExpired(jwtInHeaders, 0);
                HealthStatus s = expired ? HealthStatus.EXPIRED : HealthStatus.ACTIVE;
                return new SessionHealthResult(s, 0, 0, "JWT Probe: " + JwtInspector.getFormattedRemainingTime(jwtInHeaders), jwtInfo);
            }
            return SessionHealthResult.unconfigured();
        }

        try {
            HttpRequest probeReq = HttpRequest.httpRequestFromUrl(targetUrl).withMethod("GET");
            probeReq = authBroker.applyAuthentication(probeReq, user);

            long start = System.currentTimeMillis();
            HttpRequestResponse response = api.http().sendRequest(probeReq);
            long latency = System.currentTimeMillis() - start;

            if (response == null || response.response() == null) {
                return new SessionHealthResult(HealthStatus.UNREACHABLE, 0, latency,
                        "Server unreachable (No response from " + targetUrl + ")", jwtInfo);
            }

            int code = response.response().statusCode();
            int expected = user.getHealthCheckExpectedStatus() > 0 ? user.getHealthCheckExpectedStatus() : 200;

            if (code == expected || (expected == 200 && code >= 200 && code < 300)) {
                return new SessionHealthResult(HealthStatus.ACTIVE, code, latency,
                        String.format("Session Active (HTTP %d, %dms)%s", code, latency, jwtInfo), jwtInfo);
            } else if (code == 401) {
                return new SessionHealthResult(HealthStatus.EXPIRED, code, latency,
                        String.format("Session Expired (HTTP 401 Unauthorized)%s", jwtInfo), jwtInfo);
            } else if (code == 403) {
                return new SessionHealthResult(HealthStatus.FORBIDDEN, code, latency,
                        String.format("Access Forbidden (HTTP 403)%s", jwtInfo), jwtInfo);
            } else if (code >= 500) {
                return new SessionHealthResult(HealthStatus.SERVER_ERROR, code, latency,
                        String.format("Server Error (HTTP %d)%s", code, jwtInfo), jwtInfo);
            } else {
                return new SessionHealthResult(HealthStatus.ACTIVE, code, latency,
                        String.format("HTTP %d (%dms)%s", code, latency, jwtInfo), jwtInfo);
            }
        } catch (Exception e) {
            return new SessionHealthResult(HealthStatus.UNREACHABLE, 0, 0,
                    "Health probe error: " + e.getMessage() + jwtInfo, jwtInfo);
        }
    }
}
