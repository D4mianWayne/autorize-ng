package com.autorize.diff;

import com.autorize.model.EnforcementStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JsonStructuralDiffTest {

    @Test
    public void shouldMaskDynamicNoiseAndDetectBypass() {
        String origJson = """
                {
                    "userId": 1001,
                    "accountBalance": 5000.50,
                    "timestamp": 1729420000,
                    "nonce": "abc-123-xyz",
                    "requestId": "req_888999"
                }
                """;

        String replayedJson = """
                {
                    "userId": 1001,
                    "accountBalance": 5000.50,
                    "timestamp": 1729420120,
                    "nonce": "def-456-uvw",
                    "requestId": "req_000111"
                }
                """;

        DiffResult result = JsonStructuralDiff.compareJson(origJson, replayedJson);
        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(EnforcementStatus.BYPASSED);
        assertThat(result.getSimilarityScore()).isEqualTo(1.0);
    }

    @Test
    public void shouldDetectEnforcementWhenDataDiverges() {
        String origJson = """
                {
                    "status": "success",
                    "data": {
                        "user": "admin",
                        "secretVaultKey": "vlt_master_999"
                    }
                }
                """;

        String replayedJson = """
                {
                    "status": "error",
                    "message": "Access denied"
                }
                """;

        DiffResult result = JsonStructuralDiff.compareJson(origJson, replayedJson);
        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(EnforcementStatus.ENFORCED);
    }
}
