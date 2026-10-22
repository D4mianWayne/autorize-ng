package com.autorize.auth;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class DPoPSignerTest {

    @Test
    public void shouldGenerateValidDPoPProofHeader() throws Exception {
        DPoPSigner signer = new DPoPSigner();
        String proof = signer.generateProof("POST", "https://api.example.com/v1/transfer");

        assertThat(proof).isNotNull().isNotBlank();

        SignedJWT parsed = SignedJWT.parse(proof);
        assertThat(parsed.getHeader().getType().toString()).isEqualTo("dpop+jwt");
        assertThat(parsed.getHeader().getJWK()).isNotNull();

        assertThat(parsed.getJWTClaimsSet().getStringClaim("htm")).isEqualTo("POST");
        assertThat(parsed.getJWTClaimsSet().getStringClaim("htu")).isEqualTo("https://api.example.com/v1/transfer");
        assertThat(parsed.getJWTClaimsSet().getJWTID()).isNotBlank();
        assertThat(parsed.getJWTClaimsSet().getIssueTime()).isNotNull();
    }

    @Test
    public void shouldIncludeServerNonceAndAccessTokenHash() throws Exception {
        DPoPSigner signer = new DPoPSigner();
        String nonce = "server-issued-nonce-12345";
        String accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake";

        String proof = signer.generateProof("GET", "https://api.example.com/v1/accounts", nonce, accessToken);

        assertThat(proof).isNotNull().isNotBlank();

        SignedJWT parsed = SignedJWT.parse(proof);
        assertThat(parsed.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo(nonce);
        assertThat(parsed.getJWTClaimsSet().getStringClaim("ath")).isNotBlank();
        assertThat(parsed.getJWTClaimsSet().getStringClaim("htm")).isEqualTo("GET");
        assertThat(parsed.getJWTClaimsSet().getStringClaim("htu")).isEqualTo("https://api.example.com/v1/accounts");
    }
}
