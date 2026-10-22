package com.autorize.auth;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtInspectorTest {

    @Test
    public void shouldIdentifyValidJwtAndCheckExpiry() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        long futureExp = Instant.now().getEpochSecond() + 3600;
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"sub\":\"12345\",\"exp\":" + futureExp + "}").getBytes(StandardCharsets.UTF_8));
        String signature = "fake_signature_bytes";

        String jwt = header + "." + payload + "." + signature;

        assertThat(JwtInspector.isJwt(jwt)).isTrue();
        assertThat(JwtInspector.isExpired(jwt, 60)).isFalse();
        assertThat(JwtInspector.getExpirationEpochSeconds(jwt)).isEqualTo(futureExp);
        assertThat(JwtInspector.getSubject(jwt)).isEqualTo("12345");
        assertThat(JwtInspector.getFormattedRemainingTime(jwt)).contains("Expires in");
    }

    @Test
    public void shouldDetectExpiredToken() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        long pastExp = Instant.now().getEpochSecond() - 100;
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"sub\":\"12345\",\"exp\":" + pastExp + "}").getBytes(StandardCharsets.UTF_8));
        String signature = "fake_signature_bytes";

        String jwt = header + "." + payload + "." + signature;

        assertThat(JwtInspector.isExpired(jwt, 0)).isTrue();
        assertThat(JwtInspector.getFormattedRemainingTime(jwt)).contains("Expired");
    }

    @Test
    public void shouldExtractJwtFromHeadersText() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"alice\"}".getBytes(StandardCharsets.UTF_8));
        String jwt = header + "." + payload + ".sig123";

        String headers = "Cookie: session=abc\nAuthorization: Bearer " + jwt + "\nX-Header: val";
        String extracted = JwtInspector.findFirstJwtInText(headers);

        assertThat(extracted).isEqualTo(jwt);
    }
}
