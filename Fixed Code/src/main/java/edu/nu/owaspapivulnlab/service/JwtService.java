package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Map;

/*
 * * 7. JWT Hardening:
 *    - The JWT secret key is now loaded securely from environment variables instead of being hardcoded.
 *    - Enforces strong key size (≥ 32 bytes) and uses `HS256` algorithm with `Keys.hmacShaKeyFor(...)`.
 *    - Includes and validates 'issuer' and 'audience' claims to prevent token misuse across different contexts.
 *    - Implements both strict and lenient parsing modes for backward compatibility.
 *    - Adds short token lifetime (TTL) to limit exposure in case of compromise.
 *
 * 8. Error Handling & Logging:
 *    - Throws clear, controlled exceptions (JwtException) on token validation failure.
 *    - Prevents raw stack traces or sensitive debug information from leaking to clients.
 *    - Exceptions are centrally handled by the global exception handler for standardized error responses.
 */



/**
 * JwtService - issues and parses JWTs with hardening:
 * - secret comes from environment (app.jwt.secret)
 * - TTL from properties (app.jwt.ttl-seconds)
 * - issuer and audience are included and validated
 * - uses Keys.hmacShaKeyFor(...) and HS256
 */
@Service
public class JwtService {
     // 7. JWT Hardening: Secret key is injected securely via environment property (not hardcoded)
    @Value("${app.jwt.secret}")
    private String secret;
    // 7. JWT Hardening: Token time-to-live is configurable to limit exposure duration
    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;
     // 7. JWT Hardening: Issuer and audience values are added to strengthen claim-based validation
    @Value("${app.jwt.issuer:owasp-api-lab}")
    private String issuer;

    @Value("${app.jwt.audience:owasp-api-users}")
    private String audience;

    // derived signing key
    private Key signingKey;
    // 7. JWT Hardening: Verify that the secret is long enough for HS256 algorithm
    @PostConstruct
    private void init() {
        if (secret == null || secret.length() < 32) {
            // 8. Error Handling: Fail fast if the JWT secret is misconfigured
            throw new IllegalStateException("JWT secret must be set and at least 32 bytes long");
        }
        signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 7. JWT Hardening:
     * Issue a signed JWT with subject, claims, issuer, audience, and expiration time.
     * Ensures that every token contains validated metadata and a digital signature.
     */
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date exp = new Date(now + ttlSeconds * 1000L);

    JwtBuilder b = Jwts.builder()
        .setSubject(subject)
        .setIssuer(issuer)
        .setAudience(audience)
        .setIssuedAt(issuedAt)
        .setExpiration(exp)
        .signWith(signingKey, SignatureAlgorithm.HS256);

        if (claims != null && !claims.isEmpty()) {
            b.addClaims(claims);
        }

        return b.compact();
    }

     /**
     * 7. JWT Hardening:
     * This method issues tokens without issuer/audience for backward compatibility.
     * Such tokens are less secure and only used in legacy test flows.
     */
    public String issueWithoutIssuerAudience(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date exp = new Date(now + ttlSeconds * 1000L);

        JwtBuilder b = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(issuedAt)
                .setExpiration(exp)
                .signWith(signingKey, SignatureAlgorithm.HS256);

        if (claims != null && !claims.isEmpty()) {
            b.addClaims(claims);
        }

        return b.compact();
    }

    /**
     * 7. JWT Hardening & 8. Error Handling:
     * Strict parse — validates signature, expiry, issuer, and audience.
     * Any invalid or expired token triggers a JwtException handled by the global exception handler.
     */
    public Jws<Claims> parse(String token) throws JwtException {
        Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token);

        Claims body = jws.getBody();

        // Validate issuer
        if (issuer != null && !issuer.equals(body.getIssuer())) {
            throw new JwtException("Invalid token issuer");
        }

        // Validate audience
        if (audience != null && !audience.equals(body.getAudience())) {
            throw new JwtException("Invalid token audience");
        }

        // Expiry is already checked by parser; additional checks not required here.
        return jws;
    }

    /**
     * 7. JWT Hardening:
     * Lenient parser that skips issuer/audience validation for compatibility.
     * Still validates signature and expiry to prevent forged tokens.
     */
    public Jws<Claims> parseLenient(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token);
    }

    // Useful getters for other parts of app if needed
    public String getIssuer() { return issuer; }
    public String getAudience() { return audience; }
}
