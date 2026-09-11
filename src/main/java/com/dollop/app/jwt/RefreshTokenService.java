package com.dollop.app.jwt;

import com.dollop.app.auth.model.AuthenticationResult;

/**
 * Service-layer contract governing the complete lifecycle of refresh tokens.
 *
 * <p>This interface separates the business logic of refresh-token management from the
 * low-level JWT signing infrastructure provided by {@link JwtProvider}. While
 * {@code JwtProvider} is responsible for producing a correctly signed token string,
 * {@code RefreshTokenService} enforces the policies around when, how, and for whom
 * a new token pair is issued:</p>
 * <ul>
 *   <li>Validates the presented refresh token's signature and natural expiry using
 *       {@link JwtValidator} with {@link TokenKeyType#REFRESH}.</li>
 *   <li>Checks that the token has not been explicitly revoked via
 *       {@link TokenRevocationStore}.</li>
 *   <li>Re-loads the principal's current authorities from
 *       {@code UserLookupProvider} (never from the token — see Phase 6 Decision #1).</li>
 *   <li>Revokes the consumed refresh token before issuing a new pair, preventing replay.</li>
 *   <li>Issues a fresh access token and refresh token via {@code JwtProvider}.</li>
 * </ul>
 *
 * <h3>Refresh Token Rotation</h3>
 * <p>Every successful call to {@link #refresh(String)} results in a new refresh token.
 * The old refresh token is revoked atomically (from the caller's perspective) during the
 * same operation. This implements the "refresh token rotation" security pattern, ensuring
 * that stolen refresh tokens are detected when they are replayed after the legitimate
 * client has already rotated.</p>
 *
 * <h3>Error Behaviour</h3>
 * <p>All methods throw an unchecked exception when presented with an invalid, expired,
 * or revoked token. The specific runtime exception type is determined by the implementation;
 * the framework's default implementation ({@code DefaultRefreshTokenService}) throws a
 * subtype of {@code SecurityFrameworkException}. Callers must handle this and return
 * an appropriate HTTP 401 response to the client.</p>
 *
 * <h3>Default Implementation</h3>
 * <p>The framework registers {@code DefaultRefreshTokenService} as the default bean,
 * conditional on no other {@code RefreshTokenService} bean being present. The default
 * implementation uses {@code InMemoryTokenRevocationStore}, which is suitable only for
 * development and single-node deployments. A startup warning is logged when this
 * combination is active.</p>
 *
 * <h3>SPI Override</h3>
 * <p>To replace the default behaviour (e.g., to add device fingerprinting, sliding
 * expiry, or a persistent revocation store), expose a {@code @Bean} of type
 * {@code RefreshTokenService} in the consuming application's Spring context.</p>
 *
 * <h3>Thread Safety</h3>
 * <p>Implementations must be thread-safe. Multiple concurrent refresh requests for the
 * same principal are possible in multi-tab browser sessions or mobile apps.</p>
 *
 * @see JwtProvider
 * @see JwtValidator
 * @see TokenRevocationStore
 * @see TokenKeyType
 * @since Phase 7.1
 */
public interface RefreshTokenService {

    /**
     * Validates the provided refresh token, revokes it, and issues a new token pair.
     *
     * <p>The full processing sequence is:</p>
     * <ol>
     *   <li>Assert {@code refreshToken} is not null or blank.</li>
     *   <li>Validate the token's signature using {@link TokenKeyType#REFRESH}.</li>
     *   <li>Assert the token has not naturally expired.</li>
     *   <li>Extract the JWT ID ({@code jti} claim) and check it has not been revoked
     *       via {@link TokenRevocationStore#isRevoked(String)}.</li>
     *   <li>Extract the subject ({@code sub} claim) via
     *       {@link JwtValidator#extractSubject(String)}.</li>
     *   <li>Reload the principal's current authorities via
     *       {@code UserLookupProvider.findByIdentifier(subject)} — authorities are never
     *       read from the token (Phase 6 Decision #1).</li>
     *   <li>Revoke the consumed refresh token via
     *       {@link TokenRevocationStore#revoke(String, java.time.Instant)}.</li>
     *   <li>Generate a new access token and refresh token pair via {@link JwtProvider}.</li>
     *   <li>Return an {@link AuthenticationResult} containing the new token pair.</li>
     * </ol>
     *
     * @param refreshToken the encoded refresh JWT string received from the client;
     *                     must not be {@code null} or blank
     * @return an {@link AuthenticationResult} containing a new access token, a new
     *         refresh token, and token metadata; never {@code null}
     * @throws IllegalArgumentException if {@code refreshToken} is {@code null} or blank
     * @throws RuntimeException         (implementation-specific subtype) if the token is
     *                                  expired, has an invalid signature, has been revoked,
     *                                  or the associated principal no longer exists
     */
    AuthenticationResult refresh(String refreshToken);

    /**
     * Explicitly revokes a single refresh token, invalidating the associated session.
     *
     * <p>This method is the primary mechanism for single-session logout. After this call,
     * presenting the same refresh token to {@link #refresh(String)} must result in an
     * error. The access token issued alongside this refresh token remains valid until
     * its natural expiry — access token revocation is out of scope for this method,
     * as access tokens are short-lived by design.</p>
     *
     * <p>If the presented token is already expired or has already been revoked, this method
     * must complete without error (idempotent operation).</p>
     *
     * @param refreshToken the encoded refresh JWT string to revoke; must not be
     *                     {@code null} or blank
     * @throws IllegalArgumentException if {@code refreshToken} is {@code null} or blank
     * @throws RuntimeException         (implementation-specific subtype) if the token
     *                                  cannot be parsed (malformed, not a JWT, etc.)
     */
    void revoke(String refreshToken);

    /**
     * Revokes all active refresh tokens associated with the given principal identifier.
     *
     * <p>This method provides a "logout all devices" capability and is the primary
     * mechanism for responding to a security incident (e.g., suspected account compromise,
     * password change, or privilege revocation). After this call, all existing refresh
     * tokens for the principal are invalidated, forcing re-authentication on all active
     * sessions.</p>
     *
     * <p>The scope of this operation depends on the underlying {@link TokenRevocationStore}
     * implementation:</p>
     * <ul>
     *   <li><strong>In-memory</strong> — revokes only tokens that were issued and tracked
     *       within the current JVM instance. Tokens from other nodes in a cluster are not
     *       affected.</li>
     *   <li><strong>Distributed (Redis / DB)</strong> — revokes all tokens across all nodes
     *       by querying the store by principal identifier.</li>
     * </ul>
     *
     * <p>If no active tokens exist for the given identifier, this method must complete
     * without error.</p>
     *
     * @param principalIdentifier the unique identifier of the principal (e.g., email,
     *                            username) whose sessions are to be terminated; must not
     *                            be {@code null} or blank
     * @throws IllegalArgumentException if {@code principalIdentifier} is {@code null}
     *                                  or blank
     */
    void revokeAll(String principalIdentifier);
}
