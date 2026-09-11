package com.dollop.app.jwt.impl;

import com.dollop.app.autoconfigure.JwtProperties;
import com.dollop.app.jwt.JwtValidator;
import com.dollop.app.jwt.TokenKeyType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link JwtValidator} validating JJWT 0.12.7 tokens.
 *
 * <p>Supports dual-secret signature verification via {@link TokenKeyType} (Phase 6 Decision #2).
 * Strictly suppresses parsing exceptions on {@link #isValid} to safely return {@code false}.</p>
 *
 * @see JwtValidator
 * @see TokenKeyType
 * @since Phase 7.5
 */
@Slf4j
public class DefaultJwtValidator implements JwtValidator {

    private final JwtProperties jwtProperties;

    public DefaultJwtValidator(JwtProperties jwtProperties) {
        Assert.notNull(jwtProperties, "jwtProperties must not be null");
        this.jwtProperties = jwtProperties;
    }

    @Override
    public boolean isValid(String token, TokenKeyType keyType) {
        if (!StringUtils.hasText(token) || keyType == null) {
            return false;
        }

        try {
            String secret = (keyType == TokenKeyType.ACCESS)
                    ? jwtProperties.getAccessSecret()
                    : jwtProperties.getRefreshSecret();

            if (!StringUtils.hasText(secret)) {
                log.error("JWT secret for key type {} is not configured", keyType);
                return false;
            }

            SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);

            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("JWT validation failed for keyType {}: {}", keyType, e.getMessage());
            return false;
        }
    }

    @Override
    public Map<String, Object> extractAllClaims(String token) {
        Assert.hasText(token, "token must not be null or blank");

        Claims claims = parseClaimsUnverifiedOrWithAccessKey(token);
        return new HashMap<>(claims);
    }

    @Override
    public String extractSubject(String token) {
        Assert.hasText(token, "token must not be null or blank");

        Claims claims = parseClaimsUnverifiedOrWithAccessKey(token);
        return claims.getSubject();
    }

    private Claims parseClaimsUnverifiedOrWithAccessKey(String token) {
        String accessSecret = jwtProperties.getAccessSecret();
        if (StringUtils.hasText(accessSecret)) {
            try {
                SecretKey key = Keys.hmacShaKeyFor(accessSecret.getBytes(StandardCharsets.UTF_8));
                return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
            } catch (JwtException e) {
                // fall through to refresh secret
            }
        }
        String refreshSecret = jwtProperties.getRefreshSecret();
        if (StringUtils.hasText(refreshSecret)) {
            SecretKey key = Keys.hmacShaKeyFor(refreshSecret.getBytes(StandardCharsets.UTF_8));
            return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
        }
        throw new IllegalStateException("Neither accessSecret nor refreshSecret is configured");
    }
}
