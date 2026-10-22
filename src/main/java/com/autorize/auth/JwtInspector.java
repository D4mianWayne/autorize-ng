package com.autorize.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtInspector {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern JWT_REGEX = Pattern.compile("ey[A-Za-z0-9_-]+\\.ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

    public static boolean isJwt(String token) {
        if (token == null) return false;
        String clean = cleanToken(token);
        String[] parts = clean.split("\\.");
        return parts.length == 3 && clean.startsWith("ey");
    }

    public static String cleanToken(String token) {
        if (token == null) return "";
        String t = token.trim();
        if (t.toLowerCase().startsWith("bearer ")) {
            return t.substring(7).trim();
        }
        if (t.toLowerCase().startsWith("dpop ")) {
            return t.substring(5).trim();
        }
        return t;
    }

    public static String findFirstJwtInText(String text) {
        if (text == null) return null;
        Matcher m = JWT_REGEX.matcher(text);
        if (m.find()) {
            return m.group();
        }
        return null;
    }

    public static JsonNode getPayloadJson(String token) {
        if (!isJwt(token)) return null;
        try {
            String[] parts = cleanToken(token).split("\\.");
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);
            return MAPPER.readTree(payloadJson);
        } catch (Exception ignored) {
            return null;
        }
    }

    public static Long getExpirationEpochSeconds(String token) {
        JsonNode node = getPayloadJson(token);
        if (node != null && node.has("exp") && node.get("exp").isNumber()) {
            return node.get("exp").asLong();
        }
        return null;
    }

    public static boolean isExpired(String token, int gracePeriodSeconds) {
        Long exp = getExpirationEpochSeconds(token);
        if (exp == null) return false;
        long currentSec = Instant.now().getEpochSecond();
        return (currentSec + gracePeriodSeconds) >= exp;
    }

    public static String getSubject(String token) {
        JsonNode node = getPayloadJson(token);
        if (node != null && node.has("sub")) {
            return node.get("sub").asText();
        }
        return null;
    }

    public static String getIssuer(String token) {
        JsonNode node = getPayloadJson(token);
        if (node != null && node.has("iss")) {
            return node.get("iss").asText();
        }
        return null;
    }

    public static String getFormattedRemainingTime(String token) {
        Long exp = getExpirationEpochSeconds(token);
        if (exp == null) return "No exp claim (Never expires)";
        long now = Instant.now().getEpochSecond();
        long diff = exp - now;

        if (diff <= 0) {
            long ago = Math.abs(diff);
            if (ago < 60) return "Expired " + ago + "s ago";
            return "Expired " + (ago / 60) + "m ago";
        }

        if (diff < 60) return "Expires in " + diff + "s";
        long minutes = diff / 60;
        long secs = diff % 60;
        if (minutes < 60) return "Expires in " + minutes + "m " + secs + "s";
        long hours = minutes / 60;
        return "Expires in " + hours + "h " + (minutes % 60) + "m";
    }

    public static String getDecodedClaimsPretty(String token) {
        JsonNode node = getPayloadJson(token);
        if (node == null) return "Invalid or unparseable JWT.";
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(node);
        } catch (Exception e) {
            return node.toString();
        }
    }
}
