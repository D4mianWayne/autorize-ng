package com.autorize.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LogEntry {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class UserResult {
        @JsonProperty("userTrafficIndex")
        private int userTrafficIndex = -1;

        @JsonProperty("userLength")
        private int userLength = 0;

        @JsonProperty("status")
        private EnforcementStatus status = EnforcementStatus.PENDING;

        @JsonProperty("diffScore")
        private double diffScore = 0.0;

        @JsonProperty("diffDetails")
        private String diffDetails = "";

        public UserResult() {}

        public UserResult(int userTrafficIndex, int userLength, EnforcementStatus status, double diffScore, String diffDetails) {
            this.userTrafficIndex = userTrafficIndex;
            this.userLength = userLength;
            this.status = status;
            this.diffScore = diffScore;
            this.diffDetails = diffDetails;
        }

        public int getUserTrafficIndex() { return userTrafficIndex; }
        public void setUserTrafficIndex(int userTrafficIndex) { this.userTrafficIndex = userTrafficIndex; }

        public int getUserLength() { return userLength; }
        public void setUserLength(int userLength) { this.userLength = userLength; }

        public EnforcementStatus getStatus() { return status; }
        public void setStatus(EnforcementStatus status) { this.status = status; }

        public double getDiffScore() { return diffScore; }
        public void setDiffScore(double diffScore) { this.diffScore = diffScore; }

        public String getDiffDetails() { return diffDetails; }
        public void setDiffDetails(String diffDetails) { this.diffDetails = diffDetails; }
    }

    @JsonProperty("id")
    private int id;

    @JsonProperty("timestamp")
    private long timestamp = Instant.now().toEpochMilli();

    @JsonProperty("method")
    private String method;

    @JsonProperty("url")
    private String url;

    @JsonProperty("origTrafficIndex")
    private int origTrafficIndex = -1;

    @JsonProperty("originalLength")
    private int originalLength = 0;

    @JsonProperty("unauthTrafficIndex")
    private int unauthTrafficIndex = -1;

    @JsonProperty("unauthLength")
    private int unauthLength = 0;

    @JsonProperty("unauthStatus")
    private EnforcementStatus unauthStatus = EnforcementStatus.DISABLED;

    @JsonProperty("unauthDetails")
    private String unauthDetails = "";

    @JsonProperty("userResults")
    private Map<String, UserResult> userResults = new HashMap<>();

    public LogEntry() {}

    public LogEntry(int id, String method, String url, int origTrafficIndex, int originalLength) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.origTrafficIndex = origTrafficIndex;
        this.originalLength = originalLength;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public int getOrigTrafficIndex() { return origTrafficIndex; }
    public void setOrigTrafficIndex(int origTrafficIndex) { this.origTrafficIndex = origTrafficIndex; }

    public int getOriginalLength() { return originalLength; }
    public void setOriginalLength(int originalLength) { this.originalLength = originalLength; }

    public int getUnauthTrafficIndex() { return unauthTrafficIndex; }
    public void setUnauthTrafficIndex(int unauthTrafficIndex) { this.unauthTrafficIndex = unauthTrafficIndex; }

    public int getUnauthLength() { return unauthLength; }
    public void setUnauthLength(int unauthLength) { this.unauthLength = unauthLength; }

    public EnforcementStatus getUnauthStatus() { return unauthStatus; }
    public void setUnauthStatus(EnforcementStatus unauthStatus) { this.unauthStatus = unauthStatus; }

    public String getUnauthDetails() { return unauthDetails; }
    public void setUnauthDetails(String unauthDetails) { this.unauthDetails = unauthDetails; }

    public Map<String, UserResult> getUserResults() { return userResults; }
    public void setUserResults(Map<String, UserResult> userResults) { this.userResults = userResults; }

    public void addUserResult(String userId, UserResult result) {
        this.userResults.put(userId, result);
    }

    public UserResult getUserResult(String userId) {
        return this.userResults.get(userId);
    }
}
