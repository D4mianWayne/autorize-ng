package com.autorize.diff;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

public class JsonStructuralDiff {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern NOISE_KEY_PATTERN = Pattern.compile(
            "(?i)(timestamp|time|nonce|_csrf|csrf|session|token|request_?id|uuid|created_?at|updated_?at|etag|latency|duration|hash)"
    );

    public static boolean isJson(String text) {
        if (text == null) return false;
        String trimmed = text.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
                (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    public static DiffResult compareJson(String jsonA, String jsonB) {
        try {
            JsonNode treeA = MAPPER.readTree(jsonA);
            JsonNode treeB = MAPPER.readTree(jsonB);

            JsonNode normalizedA = sanitizeJsonTree(treeA.deepCopy());
            JsonNode normalizedB = sanitizeJsonTree(treeB.deepCopy());

            if (normalizedA.equals(normalizedB)) {
                return new DiffResult(com.autorize.model.EnforcementStatus.BYPASSED, 1.0,
                        "JSON payload structurally identical (dynamic noise masked).");
            }

            if (hasErrorIndicators(normalizedB) && !hasErrorIndicators(normalizedA)) {
                return new DiffResult(com.autorize.model.EnforcementStatus.ENFORCED, 0.0,
                        "Replayed response contains JSON error indicators (access denied).");
            }

            double similarity = calculateTreeSimilarity(normalizedA, normalizedB);

            if (similarity >= 0.90) {
                return new DiffResult(com.autorize.model.EnforcementStatus.BYPASSED, similarity,
                        String.format("JSON similarity %.1f%% indicates probable bypass.", similarity * 100));
            } else if (similarity <= 0.35) {
                return new DiffResult(com.autorize.model.EnforcementStatus.ENFORCED, similarity,
                        String.format("JSON response distinctly different (%.1f%% similarity) - access denied.", similarity * 100));
            } else {
                return new DiffResult(com.autorize.model.EnforcementStatus.AMBIGUOUS, similarity,
                        String.format("JSON structure partially matches (%.1f%% similarity).", similarity * 100));
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean hasErrorIndicators(JsonNode node) {
        if (node == null) return false;
        if (node.isObject()) {
            if (node.has("error") || node.has("errors")) return true;
            JsonNode status = node.get("status");
            if (status != null && status.isTextual()) {
                String s = status.asText().toLowerCase();
                if (s.equals("error") || s.equals("forbidden") || s.equals("unauthorized") || s.equals("failed") || s.equals("denied")) {
                    return true;
                }
            }
            JsonNode message = node.get("message");
            if (message != null && message.isTextual()) {
                String m = message.asText().toLowerCase();
                if (m.contains("denied") || m.contains("forbidden") || m.contains("unauthorized") || m.contains("not permitted")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static JsonNode sanitizeJsonTree(JsonNode node) {
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = obj.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                if (NOISE_KEY_PATTERN.matcher(entry.getKey()).find()) {
                    fields.remove();
                } else {
                    sanitizeJsonTree(entry.getValue());
                }
            }
        } else if (node.isArray()) {
            ArrayNode arr = (ArrayNode) node;
            for (JsonNode item : arr) {
                sanitizeJsonTree(item);
            }
        }
        return node;
    }

    private static double calculateTreeSimilarity(JsonNode a, JsonNode b) {
        if (a == null && b == null) return 1.0;
        if (a == null || b == null) return 0.0;
        if (a.equals(b)) return 1.0;
        if (a.getNodeType() != b.getNodeType()) return 0.0;

        if (a.isObject() && b.isObject()) {
            ObjectNode objA = (ObjectNode) a;
            ObjectNode objB = (ObjectNode) b;

            java.util.Set<String> allKeys = new java.util.HashSet<>();
            objA.fieldNames().forEachRemaining(allKeys::add);
            objB.fieldNames().forEachRemaining(allKeys::add);

            if (allKeys.isEmpty()) return 1.0;

            double matchSum = 0.0;
            for (String key : allKeys) {
                if (objA.has(key) && objB.has(key)) {
                    matchSum += calculateTreeSimilarity(objA.get(key), objB.get(key));
                }
            }
            return matchSum / allKeys.size();
        }

        if (a.isArray() && b.isArray()) {
            ArrayNode arrA = (ArrayNode) a;
            ArrayNode arrB = (ArrayNode) b;

            int lenA = arrA.size();
            int lenB = arrB.size();
            if (lenA == 0 && lenB == 0) return 1.0;
            if (lenA == 0 || lenB == 0) return 0.0;

            int maxLen = Math.max(lenA, lenB);
            int minLen = Math.min(lenA, lenB);

            double sum = 0.0;
            for (int i = 0; i < minLen; i++) {
                sum += calculateTreeSimilarity(arrA.get(i), arrB.get(i));
            }
            return sum / maxLen;
        }

        return 0.0;
    }
}
