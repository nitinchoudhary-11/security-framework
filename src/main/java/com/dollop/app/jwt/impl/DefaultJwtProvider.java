package com.dollop.app.jwt.impl;

import com.dollop.app.autoconfigure.JwtProperties;
import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.user.SecurityPrincipal;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * Default implementation of {@link JwtProvider} producing JJWT 0.12.7 signed tokens.
 *
 * <p>Uses dual-secret architecture (Phase 6 Decision #2): access tokens are signed with
 * {@code accessSecret}, refresh tokens with {@code refreshSecret}. Embeds a random {@code jti}
 * UUID in every token to support revocation tracking (Phase 6 Decision #4).</p>
 *
 * @see JwtProvider
 * @see JwtProperties
 * @since Phase 7.5
 */
@Slf4j
public class DefaultJwtProvider implements JwtProvider {

    private final JwtProperties jwtProperties;

    public DefaultJwtProvider(JwtProperties jwtProperties) {
        Assert.notNull(jwtProperties, "jwtProperties must not be null");
        this.jwtProperties = jwtProperties;
    }

    @Override
    public String generateAccessToken(SecurityPrincipal principal, Map<String, Object> customClaims) {
        Assert.notNull(principal, "principal must not be null");

        Instant now = Instant.now();
        Instant expiry = now.plus(jwtProperties.getAccessTokenExpirationMinutes(), ChronoUnit.MINUTES);
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.getAccessSecret().getBytes(StandardCharsets.UTF_8));

        var builder = Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(principal.getIdentifier())
                .issuer(jwtProperties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry));

        if (customClaims != null && !customClaims.isEmpty()) {
            customClaims.forEach((claimKey, value) -> {
                if (!"sub".equals(claimKey) && !"iss".equals(claimKey) && !"iat".equals(claimKey)
                        && !"exp".equals(claimKey) && !"jti".equals(claimKey) && !"roles".equals(claimKey)) {
                    builder.claim(claimKey, value);
                }
            });
        }

        return builder.signWith(key).compact();
    }

    @Override
    public String generateRefreshToken(SecurityPrincipal principal) {
        Assert.notNull(principal, "principal must not be null");

        Instant now = Instant.now();
        Instant expiry = now.plus(jwtProperties.getRefreshTokenExpirationDays(), ChronoUnit.DAYS);
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.getRefreshSecret().getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(principal.getIdentifier())
                .issuer(jwtProperties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(key)
                .compact();
    }
}
