package com.autorize.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.regex.Pattern;

@JsonIgnoreProperties(ignoreUnknown = true)
public class EnforcementDetector {

    public enum DetectorType {
        STATUS_CODE_EQUALS("Status code equals"),
        STATUS_CODE_NOT_EQUALS("Status code NOT equals"),
        HEADERS_CONTAIN("Headers contain (simple string)"),
        HEADERS_NOT_CONTAIN("Headers NOT contain (simple string)"),
        HEADERS_REGEX("Headers match (regex)"),
        BODY_CONTAIN("Body contains (simple string)"),
        BODY_NOT_CONTAIN("Body NOT contains (simple string)"),
        BODY_REGEX("Body match (regex)"),
        FULL_RESPONSE_CONTAIN("Full response contains"),
        FULL_RESPONSE_NOT_CONTAIN("Full response NOT contains"),
        FULL_RESPONSE_LENGTH("Full response length equals"),
        JSON_KEY_EXISTS("JSON key exists"),
        GRAPHQL_ERROR_PRESENT("GraphQL errors array present");

        private final String label;

        DetectorType(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    @JsonProperty("type")
    private DetectorType type;

    @JsonProperty("content")
    private String content;

    @JsonProperty("enabled")
    private boolean enabled;

    private transient Pattern compiledPattern;

    public EnforcementDetector() {
        this.enabled = true;
    }

    public EnforcementDetector(DetectorType type, String content) {
        this.type = type;
        this.content = content;
        this.enabled = true;
    }

    public DetectorType getType() {
        return type;
    }

    public void setType(DetectorType type) {
        this.type = type;
        this.compiledPattern = null;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
        this.compiledPattern = null;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Pattern getCompiledPattern() {
        if (compiledPattern == null && content != null) {
            try {
                compiledPattern = Pattern.compile(content, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            } catch (Exception e) {
                compiledPattern = Pattern.compile(Pattern.quote(content));
            }
        }
        return compiledPattern;
    }
}
