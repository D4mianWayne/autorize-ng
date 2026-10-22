package com.autorize.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserProfile {

    @JsonProperty("id")
    private String id;

    @JsonProperty("name")
    private String name;

    @JsonProperty("authMode")
    private AuthMode authMode = AuthMode.STATIC;

    @JsonProperty("headersText")
    private String headersText = "Cookie: session=low_privileged_token;\nAuthorization: Bearer test_token";

    // Dynamic Auth / OAuth 2.1 Fields
    @JsonProperty("tokenEndpoint")
    private String tokenEndpoint = "";

    @JsonProperty("clientId")
    private String clientId = "";

    @JsonProperty("clientSecret")
    private String clientSecret = "";

    @JsonProperty("refreshToken")
    private String refreshToken = "";

    @JsonProperty("currentAccessToken")
    private String currentAccessToken = "";

    @JsonProperty("accessTokenExpiresAtEpochMs")
    private long accessTokenExpiresAtEpochMs = 0L;

    @JsonProperty("dpopEnabled")
    private boolean dpopEnabled = false;

    @JsonProperty("serverDPoPNonce")
    private String serverDPoPNonce = "";

    // Macro Login (Automated Re-Authentication) Fields
    @JsonProperty("loginEndpoint")
    private String loginEndpoint = "";

    @JsonProperty("loginMethod")
    private String loginMethod = "POST";

    @JsonProperty("loginContentType")
    private String loginContentType = "application/json";

    @JsonProperty("loginRequestBody")
    private String loginRequestBody = "{\"username\": \"user2@example.com\", \"password\": \"Password123!\"}";

    @JsonProperty("tokenExtractionType")
    private String tokenExtractionType = "JSON_FIELD"; // JSON_FIELD, SET_COOKIE, HEADER

    @JsonProperty("tokenExtractionPath")
    private String tokenExtractionPath = "access_token"; // JSON path or cookie name

    @JsonProperty("tokenDestinationHeader")
    private String tokenDestinationHeader = "Authorization: Bearer ";

    // Health Check Probe Fields
    @JsonProperty("healthCheckEndpoint")
    private String healthCheckEndpoint = "";

    @JsonProperty("healthCheckExpectedStatus")
    private int healthCheckExpectedStatus = 200;

    // CSRF synchronization
    @JsonProperty("syncCsrf")
    private boolean syncCsrf = false;

    @JsonProperty("csrfCookieName")
    private String csrfCookieName = "XSRF-TOKEN";

    @JsonProperty("csrfHeaderName")
    private String csrfHeaderName = "X-XSRF-TOKEN";

    @JsonProperty("detectorAndLogic")
    private boolean detectorAndLogic = false;

    @JsonProperty("matchReplaceRules")
    private List<MatchReplaceRule> matchReplaceRules = new ArrayList<>();

    @JsonProperty("enforcementDetectors")
    private List<EnforcementDetector> enforcementDetectors = new ArrayList<>();

    public UserProfile() {}

    public UserProfile(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public AuthMode getAuthMode() {
        return authMode;
    }

    public void setAuthMode(AuthMode authMode) {
        this.authMode = authMode;
    }

    public String getHeadersText() {
        return headersText;
    }

    public void setHeadersText(String headersText) {
        this.headersText = headersText;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getCurrentAccessToken() {
        return currentAccessToken;
    }

    public void setCurrentAccessToken(String currentAccessToken) {
        this.currentAccessToken = currentAccessToken;
    }

    public long getAccessTokenExpiresAtEpochMs() {
        return accessTokenExpiresAtEpochMs;
    }

    public void setAccessTokenExpiresAtEpochMs(long accessTokenExpiresAtEpochMs) {
        this.accessTokenExpiresAtEpochMs = accessTokenExpiresAtEpochMs;
    }

    public boolean isDpopEnabled() {
        return dpopEnabled;
    }

    public void setDpopEnabled(boolean dpopEnabled) {
        this.dpopEnabled = dpopEnabled;
    }

    public String getServerDPoPNonce() {
        return serverDPoPNonce;
    }

    public void setServerDPoPNonce(String serverDPoPNonce) {
        this.serverDPoPNonce = serverDPoPNonce;
    }

    public String getLoginEndpoint() {
        return loginEndpoint;
    }

    public void setLoginEndpoint(String loginEndpoint) {
        this.loginEndpoint = loginEndpoint;
    }

    public String getLoginMethod() {
        return loginMethod;
    }

    public void setLoginMethod(String loginMethod) {
        this.loginMethod = loginMethod;
    }

    public String getLoginContentType() {
        return loginContentType;
    }

    public void setLoginContentType(String loginContentType) {
        this.loginContentType = loginContentType;
    }

    public String getLoginRequestBody() {
        return loginRequestBody;
    }

    public void setLoginRequestBody(String loginRequestBody) {
        this.loginRequestBody = loginRequestBody;
    }

    public String getTokenExtractionType() {
        return tokenExtractionType;
    }

    public void setTokenExtractionType(String tokenExtractionType) {
        this.tokenExtractionType = tokenExtractionType;
    }

    public String getTokenExtractionPath() {
        return tokenExtractionPath;
    }

    public void setTokenExtractionPath(String tokenExtractionPath) {
        this.tokenExtractionPath = tokenExtractionPath;
    }

    public String getTokenDestinationHeader() {
        return tokenDestinationHeader;
    }

    public void setTokenDestinationHeader(String tokenDestinationHeader) {
        this.tokenDestinationHeader = tokenDestinationHeader;
    }

    public String getHealthCheckEndpoint() {
        return healthCheckEndpoint;
    }

    public void setHealthCheckEndpoint(String healthCheckEndpoint) {
        this.healthCheckEndpoint = healthCheckEndpoint;
    }

    public int getHealthCheckExpectedStatus() {
        return healthCheckExpectedStatus;
    }

    public void setHealthCheckExpectedStatus(int healthCheckExpectedStatus) {
        this.healthCheckExpectedStatus = healthCheckExpectedStatus;
    }

    public boolean isSyncCsrf() {
        return syncCsrf;
    }

    public void setSyncCsrf(boolean syncCsrf) {
        this.syncCsrf = syncCsrf;
    }

    public String getCsrfCookieName() {
        return csrfCookieName;
    }

    public void setCsrfCookieName(String csrfCookieName) {
        this.csrfCookieName = csrfCookieName;
    }

    public String getCsrfHeaderName() {
        return csrfHeaderName;
    }

    public void setCsrfHeaderName(String csrfHeaderName) {
        this.csrfHeaderName = csrfHeaderName;
    }

    public boolean isDetectorAndLogic() {
        return detectorAndLogic;
    }

    public void setDetectorAndLogic(boolean detectorAndLogic) {
        this.detectorAndLogic = detectorAndLogic;
    }

    public List<MatchReplaceRule> getMatchReplaceRules() {
        return matchReplaceRules;
    }

    public void setMatchReplaceRules(List<MatchReplaceRule> matchReplaceRules) {
        this.matchReplaceRules = matchReplaceRules;
    }

    public List<EnforcementDetector> getEnforcementDetectors() {
        return enforcementDetectors;
    }

    public void setEnforcementDetectors(List<EnforcementDetector> enforcementDetectors) {
        this.enforcementDetectors = enforcementDetectors;
    }
}
