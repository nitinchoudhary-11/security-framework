package com.dollop.app.jwt;

import java.time.Instant;

/**
 * Service Provider Interface for tracking JWT identifiers that have been explicitly
 * revoked before their natural cryptographic expiry.
 *
 * <p>Token revocation is a necessary complement to JWT validation. Because JWTs are
 * stateless by design, a structurally valid and non-expired token cannot be invalidated
 * by the issuer without a server-side revocation record. This interface provides that
 * revocation contract for the following scenarios:</p>
 * <ul>
 *   <li>Refresh token rotation — the consumed refresh token is revoked immediately
 *       after a new pair is issued, preventing replay attacks.</li>
 *   <li>Explicit logout — the caller's active refresh token is revoked so it cannot
 *       be used to obtain further access tokens.</li>
 *   <li>Force-logout all sessions — all refresh tokens for a principal are revoked,
 *       used during security incidents or account suspension.</li>
 * </ul>
 *
 * <h3>Key Design Decisions</h3>
 * <ul>
 *   <li><strong>Keyed by JTI, not raw token string</strong> — the store tracks the JWT ID
 *       ({@code jti} claim), not the full encoded token string. This avoids storing large
 *       payloads, is format-agnostic, and allows richer querying by ID.</li>
 *   <li><strong>Expiry-aware</strong> — the {@link #revoke(String, Instant)} method accepts
 *       the token's natural expiry so that implementations can schedule cleanup. Entries do
 *       not need to live forever; once the token's natural expiry is past, it is invalid
 *       regardless of the revocation store.</li>
 *   <li><strong>Absence means not revoked</strong> — {@link #isRevoked(String)} must return
 *       {@code false} for any token ID that was never explicitly revoked. The JWT validator
 *       handles expiry independently; this store only tracks explicit revocations.</li>
 * </ul>
 *
 * <h3>Default Implementation</h3>
 * <p>The framework provides {@code InMemoryTokenRevocationStore} as the default
 * implementation. It is suitable only for development and single-node deployments.
 * A production deployment must replace this with a persistent, distributed store
 * (e.g., Redis, relational DB) by exposing a {@code @Bean} of this type.</p>
 *
 * <h3>SPI Override</h3>
 * <p>Register a {@code @Bean} of type {@code TokenRevocationStore} in the consuming
 * application's Spring context. The framework's default implementation is registered
 * with {@code @ConditionalOnMissingBean(TokenRevocationStore.class)} and will be
 * skipped when a custom bean is present.</p>
 *
 * <h3>Thread Safety</h3>
 * <p>All implementations of this interface must be thread-safe. The revocation store
 * is accessed concurrently from the JWT authentication filter (read path) and from
 * the refresh/logout service (write path).</p>
 *
 * @see RefreshTokenService
 * @see TokenKeyType
 * @since Phase 7.1
 */
public interface TokenRevocationStore {

    /**
     * Marks a token as explicitly revoked.
     *
     * <p>After this method returns, any subsequent call to {@link #isRevoked(String)} with
     * the same {@code tokenId} must return {@code true}, provided the token's natural
     * {@code expiry} has not yet passed. Implementations may use the {@code expiry} parameter
     * to schedule automatic cleanup of the revocation entry and avoid unbounded memory growth.</p>
     *
     * <p>This method is idempotent: revoking an already-revoked token must not throw
     * an exception. If the same {@code tokenId} is submitted again (e.g., due to a retry),
     * implementations should update the stored expiry to the later of the two values.</p>
     *
     * @param tokenId the JWT ID ({@code jti} claim) of the token to revoke; must not be
     *                {@code null} or blank
     * @param expiry  the instant at which the token would have naturally expired; used by
     *                implementations to bound the lifetime of the revocation entry; must not
     *                be {@code null}
     * @throws IllegalArgumentException if {@code tokenId} is {@code null} or blank,
     *                                  or if {@code expiry} is {@code null}
     */
    void revoke(String tokenId, Instant expiry);

    /**
     * Determines whether a token has been explicitly revoked.
     *
     * <p>Returns {@code true} only if the token was previously passed to
     * {@link #revoke(String, Instant)} and its revocation entry has not been purged.
     * Returns {@code false} in all other cases, including for tokens that were never
     * presented to this store.</p>
     *
     * <p>This method does not check whether the token is cryptographically valid or
     * whether it has naturally expired — those concerns belong to {@link JwtValidator}.
     * This method exclusively answers: "was this specific token ID explicitly revoked?"</p>
     *
     * @param tokenId the JWT ID ({@code jti} claim) to check; must not be {@code null}
     * @return {@code true} if the token was explicitly revoked and the revocation record
     *         is still present; {@code false} otherwise
     * @throws IllegalArgumentException if {@code tokenId} is {@code null}
     */
    boolean isRevoked(String tokenId);

    /**
     * Removes all revocation entries whose associated token expiry has passed.
     *
     * <p>This method is a lifecycle hook intended for implementations that manage in-memory
     * or time-bounded storage. It should remove all entries where the stored expiry
     * {@link Instant} is before or equal to {@link Instant#now()}, since those tokens
     * can no longer be presented as valid even without the revocation record.</p>
     *
     * <p>Implementations backed by stores with native TTL support (e.g., Redis with
     * key expiry, or a database with scheduled cleanup) may provide a no-op implementation
     * of this method, as the underlying store handles expiry automatically.</p>
     *
     * <p>The framework does not call this method on a schedule automatically. Consuming
     * applications that use the default in-memory implementation should invoke this
     * periodically (e.g., via a {@code @Scheduled} task) to prevent memory growth.</p>
     */
    void purgeExpired();
}
