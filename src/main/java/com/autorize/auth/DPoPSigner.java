package com.autorize.auth;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class DPoPSigner {

    private final ECKey ecJWK;
    private final JWSSigner signer;

    public DPoPSigner() {
        try {
            this.ecJWK = new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            this.signer = new ECDSASigner(ecJWK);
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate DPoP EC keypair", e);
        }
    }

    public String generateProof(String httpMethod, String urlString) {
        return generateProof(httpMethod, urlString, null, null);
    }

    public String generateProof(String httpMethod, String urlString, String serverNonce, String accessToken) {
        try {
            URI uri = new URI(urlString);
            String htu = uri.getScheme() + "://" + uri.getAuthority() + uri.getPath();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(ecJWK.toPublicJWK())
                    .build();

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .claim("htm", httpMethod.toUpperCase())
                    .claim("htu", htu)
                    .issueTime(new Date());

            // RFC 9449 Section 8: Server-provided DPoP Nonce
            if (serverNonce != null && !serverNonce.isBlank()) {
                claimsBuilder.claim("nonce", serverNonce.trim());
            }

            // RFC 9449 Section 4.2: Access Token Hash (ath)
            if (accessToken != null && !accessToken.isBlank()) {
                String cleanToken = JwtInspector.cleanToken(accessToken);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(cleanToken.getBytes(StandardCharsets.US_ASCII));
                String ath = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
                claimsBuilder.claim("ath", ath);
            }

            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception e) {
            return "";
        }
    }

    public ECKey getEcJWK() {
        return ecJWK;
    }
}
