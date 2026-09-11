package com.dollop.app.security.core.exception;

/**
 * Thrown when a JSON Web Token has been explicitly revoked before its natural expiry.
 *
 * <p>This exception is a specialisation of {@link SecurityFrameworkException} for the
 * case where a cryptographically valid, non-expired token has been invalidated by an
 * explicit revocation operation via {@code TokenRevocationStore}. This occurs in the
 * following scenarios:</p>
 * <ul>
 *   <li>Refresh token rotation — the consumed refresh token is revoked immediately
 *       after a new pair is issued, preventing replay of the old token.</li>
 *   <li>Explicit logout — the principal's active refresh token is revoked.</li>
 *   <li>Force-logout all sessions — all refresh tokens for a principal are revoked.</li>
 * </ul>
 *
 * <h3>Usage in Filter Chain</h3>
 * <p>Thrown by {@code JwtAuthenticationFilter} when the token passes signature and
 * expiry validation but {@code TokenRevocationStore.isRevoked(jti)} returns {@code true}.
 * Also thrown by {@code DefaultRefreshTokenService.refresh()} under the same condition.
 * The filter or service handler delegates to {@link SecurityErrorResponseWriter} to emit
 * HTTP 401 with a JSON body.</p>
 *
 * <h3>Security Note</h3>
 * <p>The error message must not reveal that the specific token was revoked (which could
 * confirm the existence of a valid session) — use a generic "Authentication failed" or
 * "Token is no longer valid" message in production configurations.</p>
 *
 * @see TokenExpiredException
 * @see SecurityFrameworkException
 * @since Phase 7.4
 */
public class TokenRevokedException extends SecurityFrameworkException {

    /**
     * Constructs a {@code TokenRevokedException} with the standard HTTP 401 status.
     *
     * @param message a human-readable description of the revocation condition;
     *                should be generic to avoid revealing session existence
     */
    public TokenRevokedException(String message) {
        super(message, 401);
    }

    /**
     * Constructs a {@code TokenRevokedException} with the standard HTTP 401 status
     * and an underlying cause.
     *
     * @param message a human-readable description of the revocation condition
     * @param cause   the underlying exception that triggered revocation detection
     */
    public TokenRevokedException(String message, Throwable cause) {
        super(message, cause, 401);
    }
}
