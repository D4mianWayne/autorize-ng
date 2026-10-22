package com.autorize.diff;

import com.autorize.model.EnforcementStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class GraphQLAnalyzerTest {

    @Test
    public void shouldDetectGraphQLContentType() {
        boolean isGql = GraphQLAnalyzer.isGraphQL("https://api.example.com/graphql", "{\"query\":\"{ me { id } }\"}", "{\"data\":{\"me\":{\"id\":\"1\"}}}");
        assertThat(isGql).isTrue();
    }

    @Test
    public void shouldDetectGraphQLEnforcementWhenErrorsReturned() {
        String orig = "{\"data\":{\"user\":{\"id\":\"1001\",\"salary\":150000}}}";
        String replayed = "{\"data\":null,\"errors\":[{\"message\":\"Unauthorized field access\"}]}";

        DiffResult result = GraphQLAnalyzer.evaluateGraphQL(orig, replayed);
        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(EnforcementStatus.ENFORCED);
    }

    @Test
    public void shouldDetectGraphQLBypassWhenDataIdentical() {
        String orig = "{\"data\":{\"user\":{\"id\":\"1001\",\"salary\":150000}}}";
        String replayed = "{\"data\":{\"user\":{\"id\":\"1001\",\"salary\":150000}}}";

        DiffResult result = GraphQLAnalyzer.evaluateGraphQL(orig, replayed);
        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(EnforcementStatus.BYPASSED);
    }
}
