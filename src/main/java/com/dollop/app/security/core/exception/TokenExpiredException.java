package com.dollop.app.security.core.exception;

/**
 * Thrown when a JSON Web Token has passed its natural expiry ({@code exp} claim).
 *
 * <p>This exception is a specialisation of {@link SecurityFrameworkException} for the
 * specific case where a cryptographically valid token is rejected because the current
 * time has passed the token's {@code exp} claim. It is distinct from a token that fails
 * signature verification ({@code BadCredentialsException}) or has been explicitly revoked
 * ({@link TokenRevokedException}).</p>
 *
 * <h3>Usage in Filter Chain</h3>
 * <p>Thrown by {@code JwtAuthenticationFilter} when
 * {@code JwtValidator.isValid(token, ACCESS)} returns {@code false} specifically due to
 * expiry. The filter catches this and delegates to {@link SecurityErrorResponseWriter}
 * to emit HTTP 401 with a JSON body. The expiry message is intentionally generic to
 * avoid leaking token timing details.</p>
 *
 * <h3>Client Behaviour</h3>
 * <p>Clients receiving HTTP 401 with an expiry-indicating body should submit their
 * refresh token to the token-refresh endpoint to obtain a new access token. If the
 * refresh token has also expired, the client must re-authenticate.</p>
 *
 * @see TokenRevokedException
 * @see SecurityFrameworkException
 * @since Phase 7.4
 */
public class TokenExpiredException extends SecurityFrameworkException {

    /**
     * Constructs a {@code TokenExpiredException} with the standard HTTP 401 status.
     *
     * @param message a human-readable description of why the token was considered expired;
     *                should not reveal internal token details
     */
    public TokenExpiredException(String message) {
        super(message, 401);
    }

    /**
     * Constructs a {@code TokenExpiredException} with the standard HTTP 401 status
     * and an underlying cause.
     *
     * @param message a human-readable description of the expiry condition
     * @param cause   the underlying exception from the JWT parsing library
     */
    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause, 401);
    }
}
