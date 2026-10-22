package com.autorize.model;

import java.util.Set;

public enum HttpMethod {
    GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT;

    private static final Set<HttpMethod> SAFE_METHODS = Set.of(GET, HEAD, OPTIONS);
    private static final Set<HttpMethod> IDEMPOTENT_METHODS = Set.of(GET, HEAD, OPTIONS, PUT, DELETE);

    public boolean isSafe() {
        return SAFE_METHODS.contains(this);
    }

    public boolean isIdempotent() {
        return IDEMPOTENT_METHODS.contains(this);
    }

    public static HttpMethod fromString(String method) {
        if (method == null) return GET;
        try {
            return HttpMethod.valueOf(method.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return GET;
        }
    }
}
