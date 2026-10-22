package com.autorize.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AutorizeConfigBundleTest {

    @Test
    void shouldSerializeAndDeserializeFullConfigBundle() throws Exception {
        ObjectMapper mapper = new ObjectMapper();

        AutorizeConfigBundle bundle = new AutorizeConfigBundle();
        bundle.setCheckUnauthenticated(true);
        bundle.setSafeMethodsOnly(false);
        bundle.setInterceptProxy(true);
        bundle.setInterceptRepeater(false);
        bundle.setIgnoreExtensions(true);

        UserProfile user = new UserProfile("u1", "Admin Context");
        user.setHeadersText("Authorization: Bearer test_token");
        user.getMatchReplaceRules().add(new MatchReplaceRule(
                MatchReplaceRule.RuleType.QUERY_PARAM_STRING,
                "userId=100",
                "userId=200"
        ));
        bundle.setUserProfiles(List.of(user));

        InterceptionFilter filter = new InterceptionFilter(
                InterceptionFilter.FilterType.URL_CONTAINS_STRING,
                "/api/v2"
        );
        bundle.setInterceptionFilters(List.of(filter));

        EnforcementDetector detector = new EnforcementDetector(
                EnforcementDetector.DetectorType.STATUS_CODE_EQUALS,
                "403"
        );
        bundle.setUnauthDetectors(List.of(detector));

        String json = mapper.writeValueAsString(bundle);
        assertThat(json).contains("Admin Context");
        assertThat(json).contains("QUERY_PARAM_STRING");

        AutorizeConfigBundle read = mapper.readValue(json, AutorizeConfigBundle.class);
        assertThat(read.getUserProfiles()).hasSize(1);
        assertThat(read.getUserProfiles().get(0).getName()).isEqualTo("Admin Context");
        assertThat(read.getUserProfiles().get(0).getMatchReplaceRules().get(0).getType())
                .isEqualTo(MatchReplaceRule.RuleType.QUERY_PARAM_STRING);
        assertThat(read.getInterceptRepeater()).isFalse();
        assertThat(read.getIgnoreExtensions()).isTrue();
    }
}
