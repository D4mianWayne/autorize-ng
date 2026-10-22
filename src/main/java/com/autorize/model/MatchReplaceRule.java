package com.autorize.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.regex.Pattern;

@JsonIgnoreProperties(ignoreUnknown = true)
public class MatchReplaceRule {

    public enum RuleType {
        HEADER_STRING("Header (simple string)"),
        HEADER_REGEX("Header (regex)"),
        PATH_STRING("Path (simple string)"),
        PATH_REGEX("Path (regex)"),
        BODY_STRING("Body (simple string)"),
        BODY_REGEX("Body (regex)"),
        QUERY_PARAM_STRING("Query Param (key=value)"),
        QUERY_PARAM_REGEX("Query Param (regex)"),
        JSON_FIELD("JSON Field Key/Value");

        private final String label;

        RuleType(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    @JsonProperty("type")
    private RuleType type;

    @JsonProperty("match")
    private String match;

    @JsonProperty("replace")
    private String replace;

    @JsonProperty("enabled")
    private boolean enabled;

    private transient Pattern compiledPattern;

    public MatchReplaceRule() {
        this.enabled = true;
    }

    public MatchReplaceRule(RuleType type, String match, String replace) {
        this.type = type;
        this.match = match;
        this.replace = replace;
        this.enabled = true;
    }

    public RuleType getType() {
        return type;
    }

    public void setType(RuleType type) {
        this.type = type;
        this.compiledPattern = null;
    }

    public String getMatch() {
        return match;
    }

    public void setMatch(String match) {
        this.match = match;
        this.compiledPattern = null;
    }

    public String getReplace() {
        return replace;
    }

    public void setReplace(String replace) {
        this.replace = replace;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Pattern getCompiledPattern() {
        if (compiledPattern == null && match != null) {
            try {
                compiledPattern = Pattern.compile(match, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            } catch (Exception e) {
                compiledPattern = Pattern.compile(Pattern.quote(match));
            }
        }
        return compiledPattern;
    }
}
