package com.dollop.app.security.core.exception;

/**
 * Thrown when authentication is rejected because the principal's account is locked.
 *
 * <p>This exception is a specialisation of {@link SecurityFrameworkException} for the
 * case where a token is structurally valid and not revoked, but the associated account
 * has been locked since the token was issued. This enforces the principle that account
 * lock state is always reloaded from {@code UserLookupProvider} rather than trusted
 * from the token — per Phase 6 Decision #1.</p>
 *
 * <h3>When Thrown</h3>
 * <ul>
 *   <li>In {@code JwtAuthenticationFilter}, after successfully validating the token and
 *       loading the principal via {@code UserLookupProvider}, if
 *       {@code SecurityPrincipal.isAccountLocked()} returns {@code true}.</li>
 *   <li>In {@code DefaultRefreshTokenService.refresh()}, after loading the principal to
 *       issue a new token pair, if the account has been locked since the refresh token
 *       was issued.</li>
 * </ul>
 *
 * <h3>HTTP Status</h3>
 * <p>The HTTP response status depends on the {@code security.core.hide-account-state}
 * property (Phase 6 Decision #10):</p>
 * <ul>
 *   <li>{@code hide-account-state=false} (default): HTTP 423 Locked — signals to the
 *       client that the account exists but is locked.</li>
 *   <li>{@code hide-account-state=true}: HTTP 401 Unauthorized — a generic response
 *       that does not reveal the lock state.</li>
 * </ul>
 * <p>The HTTP status stored in this exception is always 423. The
 * {@code SecurityErrorResponseWriter} or entry point selects the outbound status based
 * on the property.</p>
 *
 * @see SecurityFrameworkException
 * @see TokenExpiredException
 * @since Phase 7.4
 */
public class AccountLockedException extends SecurityFrameworkException {

    /**
     * Constructs an {@code AccountLockedException} with HTTP status 423 (Locked).
     *
     * @param message a human-readable description of the lock condition; use a generic
     *                message when {@code security.core.hide-account-state=true} is active
     */
    public AccountLockedException(String message) {
        super(message, 423);
    }

    /**
     * Constructs an {@code AccountLockedException} with HTTP status 423 (Locked)
     * and an underlying cause.
     *
     * @param message a human-readable description of the lock condition
     * @param cause   the underlying exception that detected the lock state
     */
    public AccountLockedException(String message, Throwable cause) {
        super(message, cause, 423);
    }
}
