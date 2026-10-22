package com.autorize.diff;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.autorize.model.EnforcementDetector;
import com.autorize.model.EnforcementStatus;

import java.util.List;

public class DiffEngine {

    public DiffResult evaluateBypass(HttpResponse origResponse, HttpResponse replayedResponse,
                                     String targetUrl, String requestBody,
                                     List<EnforcementDetector> detectors, boolean isAndLogic) {

        if (replayedResponse == null) {
            return new DiffResult(EnforcementStatus.ERROR, 0.0, "Replayed request failed to receive a response.");
        }

        int origCode = origResponse.statusCode();
        int replayedCode = replayedResponse.statusCode();
        String origBody = origResponse.bodyToString();
        String replayedBody = replayedResponse.bodyToString();

        // 1. Explicit 401 / 403 on replayed request
        if ((replayedCode == 401 || replayedCode == 403) && origCode < 400) {
            return new DiffResult(EnforcementStatus.ENFORCED, 0.0,
                    String.format("HTTP %d Forbidden/Unauthorized returned.", replayedCode));
        }

        // 2. Server Error (500) divergence - potential unhandled exception or crash
        if (replayedCode >= 500 && origCode < 500) {
            return new DiffResult(EnforcementStatus.AMBIGUOUS, 0.0,
                    String.format("Server error HTTP %d occurred on replayed request. Investigate for unhandled exceptions.", replayedCode));
        }

        // 3. User-configured Enforcement Detectors
        if (detectors != null && !detectors.isEmpty()) {
            boolean matched = evaluateDetectors(replayedResponse, detectors, isAndLogic);
            if (matched) {
                return new DiffResult(EnforcementStatus.ENFORCED, 0.0, "Matched configured enforcement detector fingerprint.");
            }
        }

        // 4. GraphQL Aware Evaluation
        if (GraphQLAnalyzer.isGraphQL(targetUrl, requestBody, origBody)) {
            DiffResult gqlResult = GraphQLAnalyzer.evaluateGraphQL(origBody, replayedBody);
            if (gqlResult != null) {
                return gqlResult;
            }
        }

        // 5. JSON Structural Diff
        if (JsonStructuralDiff.isJson(origBody) && JsonStructuralDiff.isJson(replayedBody)) {
            DiffResult jsonResult = JsonStructuralDiff.compareJson(origBody, replayedBody);
            if (jsonResult != null) {
                return jsonResult;
            }
        }

        // 6. Status code divergence
        if (origCode != replayedCode) {
            return new DiffResult(EnforcementStatus.ENFORCED, 0.0,
                    String.format("Status codes diverge: Orig HTTP %d vs Replayed HTTP %d.", origCode, replayedCode));
        }

        // 7. Exact String Equality
        if (origBody.equals(replayedBody)) {
            return new DiffResult(EnforcementStatus.BYPASSED, 1.0, "Responses are 100% byte-for-byte identical.");
        }

        // 8. Body Length Fallback
        int origLen = origBody.length();
        int replayedLen = replayedBody.length();
        if (origLen == replayedLen) {
            return new DiffResult(EnforcementStatus.BYPASSED, 0.99, "Response body lengths are identical.");
        }

        double lenDiffPercent = Math.abs(origLen - replayedLen) / (double) Math.max(origLen, 1);
        if (lenDiffPercent < 0.02) {
            return new DiffResult(EnforcementStatus.AMBIGUOUS, 0.95,
                    String.format("Body length differs by only %.1f%% (%d vs %d bytes).", lenDiffPercent * 100, origLen, replayedLen));
        }

        return new DiffResult(EnforcementStatus.AMBIGUOUS, 0.5,
                String.format("Content differs (Orig: %d bytes, Replayed: %d bytes).", origLen, replayedLen));
    }

    private boolean evaluateDetectors(HttpResponse response, List<EnforcementDetector> detectors, boolean isAndLogic) {
        if (detectors.isEmpty()) return false;

        boolean overallResult = isAndLogic;

        for (EnforcementDetector detector : detectors) {
            if (!detector.isEnabled()) continue;
            boolean match = checkDetector(response, detector);

            if (isAndLogic) {
                if (!match) return false;
            } else {
                if (match) return true;
            }
        }

        return overallResult;
    }

    private boolean checkDetector(HttpResponse response, EnforcementDetector detector) {
        String content = detector.getContent() != null ? detector.getContent() : "";
        String body = response.bodyToString();
        String fullResponse = response.toString();

        switch (detector.getType()) {
            case STATUS_CODE_EQUALS:
                return String.valueOf(response.statusCode()).equals(content.trim());
            case STATUS_CODE_NOT_EQUALS:
                return !String.valueOf(response.statusCode()).equals(content.trim());
            case HEADERS_CONTAIN:
                return response.headers().stream().anyMatch(h -> h.toString().contains(content));
            case HEADERS_NOT_CONTAIN:
                return response.headers().stream().noneMatch(h -> h.toString().contains(content));
            case HEADERS_REGEX:
                return response.headers().stream().anyMatch(h -> detector.getCompiledPattern().matcher(h.toString()).find());
            case BODY_CONTAIN:
                return body.contains(content);
            case BODY_NOT_CONTAIN:
                return !body.contains(content);
            case BODY_REGEX:
                return detector.getCompiledPattern().matcher(body).find();
            case FULL_RESPONSE_CONTAIN:
                return fullResponse.contains(content);
            case FULL_RESPONSE_NOT_CONTAIN:
                return !fullResponse.contains(content);
            case FULL_RESPONSE_LENGTH:
                try {
                    int expectedLen = Integer.parseInt(content.trim());
                    return response.body().length() == expectedLen;
                } catch (NumberFormatException e) {
                    return false;
                }
            default:
                return false;
        }
    }
}
