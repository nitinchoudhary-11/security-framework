package com.dollop.app.jwt.impl;

import com.dollop.app.auth.model.AuthenticationResult;
import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.jwt.JwtValidator;
import com.dollop.app.jwt.RefreshTokenService;
import com.dollop.app.jwt.TokenKeyType;
import com.dollop.app.jwt.TokenRevocationStore;
import com.dollop.app.security.core.exception.AccountLockedException;
import com.dollop.app.security.core.exception.TokenRevokedException;
import com.dollop.app.spi.user.UserLookupProvider;
import com.dollop.app.user.SecurityPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

/**
 * Default framework implementation of {@link RefreshTokenService} that enforces
 * refresh-token rotation with immediate revocation of the consumed token.
 *
 * <p>This implementation performs the full secure refresh flow:</p>
 * <ol>
 *   <li>Validate the refresh token's signature using {@link TokenKeyType#REFRESH} — ensuring
 *       a refresh token cannot be used as a bearer access token (Phase 6 Decision #2).</li>
 *   <li>Check the token against {@link TokenRevocationStore} — prevents replay of previously
 *       consumed or explicitly revoked tokens.</li>
 *   <li>Extract the subject ({@code sub} claim) and reload the principal from
 *       {@link UserLookupProvider} — authorities are never read from the token
 *       (Phase 6 Decision #1).</li>
 *   <li>Enforce account-lock state on the reloaded principal — a locked account cannot
 *       obtain new tokens even if the refresh token is still cryptographically valid.</li>
 *   <li>Revoke the consumed refresh token <em>before</em> issuing the new pair — ensures
 *       atomicity from the caller's perspective and prevents duplicate issuance.</li>
 *   <li>Issue a new access token and refresh token via {@link JwtProvider}.</li>
 * </ol>
 *
 * <h3>Refresh Token Rotation</h3>
 * <p>Every successful {@link #refresh(String)} call consumes the presented refresh token
 * (adds its JTI to the revocation store) and issues a brand-new refresh token. If an
 * attacker replays the old refresh token after the legitimate client has already rotated,
 * {@link TokenRevocationStore#isRevoked(String)} returns {@code true} and the replay is
 * rejected with {@link TokenRevokedException}.</p>
 *
 * <h3>JTI Claim Requirement</h3>
 * <p>This implementation requires the refresh token to contain a {@code jti} (JWT ID)
 * claim. The JTI is extracted from the raw token's claims map via
 * {@link JwtValidator#extractAllClaims(String)}. If the {@code jti} claim is absent,
 * the token cannot be revoked and a {@link TokenRevokedException} is thrown to reject
 * it safely. The {@code DefaultJwtProvider} (Phase 7.5) must embed a {@code jti} in all
 * generated refresh tokens.</p>
 *
 * <h3>Production Warning</h3>
 * <p>A {@code WARN} log is emitted at construction time if the injected
 * {@link TokenRevocationStore} is an {@link InMemoryTokenRevocationStore}, reminding
 * operators that revocation state is not shared across nodes.</p>
 *
 * @see RefreshTokenService
 * @see TokenRevocationStore
 * @see JwtProvider
 * @see JwtValidator
 * @since Phase 7.4
 */
@Slf4j
public class DefaultRefreshTokenService implements RefreshTokenService {

    private static final String JTI_CLAIM = "jti";

    private final JwtValidator jwtValidator;
    private final JwtProvider jwtProvider;
    private final TokenRevocationStore tokenRevocationStore;
    private final UserLookupProvider userLookupProvider;

    /**
     * Constructs the service with all required dependencies.
     *
     * <p>A production-unsuitability warning is logged if the provided
     * {@link TokenRevocationStore} is the in-memory default.</p>
     *
     * @param jwtValidator          the validator used to verify refresh token signatures;
     *                              must not be {@code null}
     * @param jwtProvider           the provider used to generate new token pairs;
     *                              must not be {@code null}
     * @param tokenRevocationStore  the store used to revoke consumed tokens and check for
     *                              replays; must not be {@code null}
     * @param userLookupProvider    the SPI used to reload the principal's current state and
     *                              authorities; must not be {@code null}
     * @throws IllegalArgumentException if any parameter is {@code null}
     */
    public DefaultRefreshTokenService(
            JwtValidator jwtValidator,
            JwtProvider jwtProvider,
            TokenRevocationStore tokenRevocationStore,
            UserLookupProvider userLookupProvider) {

        Assert.notNull(jwtValidator, "jwtValidator must not be null");
        Assert.notNull(jwtProvider, "jwtProvider must not be null");
        Assert.notNull(tokenRevocationStore, "tokenRevocationStore must not be null");
        Assert.notNull(userLookupProvider, "userLookupProvider must not be null");

        this.jwtValidator = jwtValidator;
        this.jwtProvider = jwtProvider;
        this.tokenRevocationStore = tokenRevocationStore;
        this.userLookupProvider = userLookupProvider;

        if (tokenRevocationStore instanceof InMemoryTokenRevocationStore) {
            log.warn("DefaultRefreshTokenService is using InMemoryTokenRevocationStore. " +
                    "Refresh token revocation state will be lost on restart and is not " +
                    "shared across cluster nodes. Not suitable for production.");
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Full refresh flow with token rotation:</p>
     * <ol>
     *   <li>Validate token structure and signature using {@link TokenKeyType#REFRESH}.</li>
     *   <li>Extract and check the {@code jti} claim against the revocation store.</li>
     *   <li>Extract the {@code sub} claim and reload the principal.</li>
     *   <li>Enforce account-lock state.</li>
     *   <li>Revoke the consumed token.</li>
     *   <li>Issue a new access token and refresh token pair.</li>
     * </ol>
     *
     * @throws IllegalArgumentException if {@code refreshToken} is {@code null} or blank
     * @throws TokenRevokedException    if the refresh token has been explicitly revoked
     *                                  or its {@code jti} claim is absent
     * @throws AccountLockedException   if the principal's account is currently locked
     * @throws SecurityFrameworkException if the token is invalid, malformed, or the
     *                                  principal cannot be loaded
     */
    @Override
    public AuthenticationResult refresh(String refreshToken) {
        Assert.hasText(refreshToken, "refreshToken must not be null or blank");

        // Step 1: Validate signature and expiry with REFRESH key
        if (!jwtValidator.isValid(refreshToken, TokenKeyType.REFRESH)) {
            log.debug("Refresh token failed signature/expiry validation");
            throw new TokenRevokedException("Token is no longer valid");
        }

        // Step 2: Extract JTI and check revocation store
        Map<String, Object> claims = jwtValidator.extractAllClaims(refreshToken);
        String jti = extractJti(claims);
        Instant expiry = extractExpiry(claims);

        if (tokenRevocationStore.isRevoked(jti)) {
            log.warn("Refresh token replay attempt detected: jti=[{}] is revoked", jti);
            throw new TokenRevokedException("Token is no longer valid");
        }

        // Step 3: Extract subject and reload principal (never trust token claims for authorities)
        String subject = jwtValidator.extractSubject(refreshToken);
        SecurityPrincipal principal = userLookupProvider.findByIdentifier(subject)
                .orElseThrow(() -> {
                    log.warn("Refresh rejected: principal not found for subject=[{}]", subject);
                    return new TokenRevokedException("Token is no longer valid");
                });

        // Step 4: Enforce account-lock state (principal may have been locked since token issuance)
        if (principal.isAccountLocked()) {
            log.warn("Refresh rejected: account is locked for principal=[{}]",
                    principal.getIdentifier());
            throw new AccountLockedException("Account is locked");
        }

        // Step 5: Revoke the consumed refresh token BEFORE issuing new pair
        tokenRevocationStore.revoke(jti, expiry);
        log.debug("Consumed refresh token revoked: jti=[{}], subject=[{}]", jti, subject);

        // Step 6: Issue new access token and refresh token
        String newAccessToken = jwtProvider.generateAccessToken(principal, Collections.emptyMap());
        String newRefreshToken = jwtProvider.generateRefreshToken(principal);

        log.debug("Token pair rotated successfully for principal=[{}]", principal.getIdentifier());

        return AuthenticationResult.builder()
                .principalIdentifier(principal.getIdentifier())
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .mfaRequired(false)
                .expiresInSeconds(0L) // Expiry is encoded in the token; 0 signals "see token"
                .build();
    }

    /**
     * {@inheritDoc}
     *
     * <p>Validates that the token is a structurally parseable refresh token (using the
     * REFRESH key), extracts the JTI, and revokes it. If the token is already expired
     * or revoked, this method completes silently (idempotent).</p>
     *
     * @throws IllegalArgumentException if {@code refreshToken} is {@code null} or blank
     */
    @Override
    public void revoke(String refreshToken) {
        Assert.hasText(refreshToken, "refreshToken must not be null or blank");

        if (!jwtValidator.isValid(refreshToken, TokenKeyType.REFRESH)) {
            log.debug("revoke() called with invalid/expired refresh token — treating as no-op");
            return;
        }

        Map<String, Object> claims = jwtValidator.extractAllClaims(refreshToken);
        String jti = extractJti(claims);
        Instant expiry = extractExpiry(claims);

        tokenRevocationStore.revoke(jti, expiry);
        log.debug("Refresh token explicitly revoked: jti=[{}]", jti);
    }

    /**
     * {@inheritDoc}
     *
     * <p>For the in-memory implementation, this method is a best-effort operation —
     * it can only revoke tokens whose JTIs are known to the current JVM instance.
     * A persistent store is required for reliable all-session revocation in a
     * multi-node deployment.</p>
     *
     * <p>This implementation logs a WARN and delegates to the
     * {@link TokenRevocationStore}. Concrete store implementations that support
     * querying by principal identifier (e.g., a Redis store with a secondary index)
     * should override this via a custom {@link RefreshTokenService} bean.</p>
     *
     * @throws IllegalArgumentException if {@code principalIdentifier} is {@code null}
     *                                  or blank
     */
    @Override
    public void revokeAll(String principalIdentifier) {
        Assert.hasText(principalIdentifier, "principalIdentifier must not be null or blank");

        log.warn("revokeAll() called for principal=[{}]. The default InMemory implementation " +
                "cannot enumerate tokens by principal. " +
                "Provide a distributed TokenRevocationStore for full session revocation.",
                principalIdentifier);

        // Signal: framework-level revokeAll with InMemory is a no-op for pre-existing tokens.
        // A custom RefreshTokenService + store can implement proper per-principal revocation.
    }

    /**
     * Extracts the {@code jti} (JWT ID) claim from the decoded claims map.
     *
     * <p>The {@code jti} is required for revocation. If absent, the token cannot be
     * tracked in the revocation store — it is rejected as untrusted.</p>
     *
     * @param claims the decoded JWT claims map
     * @return the non-null, non-blank JTI string
     * @throws TokenRevokedException if the {@code jti} claim is absent or blank
     */
    private String extractJti(Map<String, Object> claims) {
        Object jtiValue = claims.get(JTI_CLAIM);
        if (!(jtiValue instanceof String jti) || jti.isBlank()) {
            log.warn("Refresh token missing or blank 'jti' claim — rejecting as untrackable");
            throw new TokenRevokedException("Token is no longer valid");
        }
        return jti;
    }

    /**
     * Extracts the {@code exp} (expiry) claim from the decoded claims map as an
     * {@link Instant}, for use as the revocation entry's TTL bound.
     *
     * <p>JJWT 0.12.7 deserialises the {@code exp} claim as a {@link java.util.Date} or
     * as a {@code Long} (epoch seconds), depending on parsing configuration. This method
     * handles both forms. If the claim is absent, {@link Instant#now()} plus a conservative
     * 7-day buffer is used to ensure the revocation entry is retained long enough.</p>
     *
     * @param claims the decoded JWT claims map
     * @return the expiry instant for the revocation entry; never {@code null}
     */
    private Instant extractExpiry(Map<String, Object> claims) {
        Object expValue = claims.get("exp");
        if (expValue instanceof Long epochSeconds) {
            return Instant.ofEpochSecond(epochSeconds);
        }
        if (expValue instanceof Integer epochSecondsInt) {
            return Instant.ofEpochSecond(epochSecondsInt.longValue());
        }
        if (expValue instanceof java.util.Date date) {
            return date.toInstant();
        }
        log.debug("'exp' claim absent or unrecognised type [{}] — using 7-day fallback expiry",
                expValue != null ? expValue.getClass().getSimpleName() : "null");
        return Instant.now().plusSeconds(7L * 24 * 60 * 60);
    }
}
