package com.autorize.model;

public enum AuthMode {
    STATIC("Static Headers / Cookies"),
    OAUTH2_REFRESH("OAuth 2.0 / 2.1 (Refresh Token Rotation)"),
    OAUTH2_CLIENT_CREDENTIALS("OAuth 2.0 (Client Credentials Grant)"),
    DPOP_OAUTH2("RFC 9449 DPoP (Proof-of-Possession Token)"),
    CUSTOM_LOGIN("Automated Macro Re-Login (JSON/Form API)");

    private final String description;

    AuthMode(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description;
    }
}
