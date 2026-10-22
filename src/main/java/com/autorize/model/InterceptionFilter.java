package com.autorize.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.regex.Pattern;

@JsonIgnoreProperties(ignoreUnknown = true)
public class InterceptionFilter {

    public enum FilterType {
        SCOPE_ONLY("Scope items only"),
        URL_CONTAINS_STRING("URL contains (simple string)"),
        URL_NOT_CONTAINS_STRING("URL NOT contains (simple string)"),
        URL_CONTAINS_REGEX("URL matches (regex)"),
        URL_NOT_CONTAINS_REGEX("URL NOT matches (regex)"),
        REQUEST_BODY_CONTAINS("Request body contains"),
        RESPONSE_BODY_CONTAINS("Response body contains"),
        REQUEST_HEADER_CONTAINS("Request header contains"),
        RESPONSE_HEADER_CONTAINS("Response header contains"),
        ONLY_METHODS("Only HTTP methods (newline separated)"),
        IGNORE_METHODS("Ignore HTTP methods (newline separated)"),
        IGNORE_OPTIONS("Ignore OPTIONS requests");

        private final String label;

        FilterType(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    @JsonProperty("type")
    private FilterType type;

    @JsonProperty("content")
    private String content;

    @JsonProperty("enabled")
    private boolean enabled;

    private transient Pattern compiledPattern;

    public InterceptionFilter() {
        this.enabled = true;
    }

    public InterceptionFilter(FilterType type, String content) {
        this.type = type;
        this.content = content;
        this.enabled = true;
    }

    public FilterType getType() {
        return type;
    }

    public void setType(FilterType type) {
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
