package com.autorize.diff;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class GraphQLAnalyzer {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static boolean isGraphQL(String url, String requestBody, String responseBody) {
        if (url != null && url.toLowerCase().contains("/graphql")) {
            return true;
        }
        if (requestBody != null && (requestBody.contains("\"query\"") || requestBody.contains("\"mutation\""))) {
            return true;
        }
        if (responseBody != null && responseBody.trim().startsWith("{")) {
            try {
                JsonNode root = MAPPER.readTree(responseBody);
                return root.has("data") || root.has("errors");
            } catch (Exception ignored) {}
        }
        return false;
    }

    public static DiffResult evaluateGraphQL(String origResponseBody, String replayedResponseBody) {
        try {
            JsonNode orig = MAPPER.readTree(origResponseBody);
            JsonNode replayed = MAPPER.readTree(replayedResponseBody);

            boolean origHasData = orig.has("data") && !orig.get("data").isNull() && !orig.get("data").isEmpty();
            boolean replayedHasErrors = replayed.has("errors") && !replayed.get("errors").isEmpty();
            boolean replayedHasNoData = !replayed.has("data") || replayed.get("data").isNull() || replayed.get("data").isEmpty();

            // If replayed response has errors and no data, authorization is enforced
            if (replayedHasErrors && replayedHasNoData) {
                return new DiffResult(com.autorize.model.EnforcementStatus.ENFORCED, 0.1,
                        "GraphQL access denied: 'errors' present and 'data' is null.");
            }

            // If both returned the exact same data payload
            if (origHasData && replayed.has("data")) {
                if (orig.get("data").equals(replayed.get("data"))) {
                    return new DiffResult(com.autorize.model.EnforcementStatus.BYPASSED, 1.0,
                            "GraphQL data payload identical between high-priv and low-priv contexts.");
                } else {
                    return new DiffResult(com.autorize.model.EnforcementStatus.ENFORCED, 0.5,
                            "GraphQL data payload differs (field-level enforcement).");
                }
            }
        } catch (Exception ignored) {}

        return null;
    }
}
