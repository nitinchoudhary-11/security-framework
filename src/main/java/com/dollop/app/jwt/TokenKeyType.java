package com.dollop.app.jwt;

/**
 * Identifies which cryptographic key context should be used when signing or validating
 * a JSON Web Token within the security framework.
 *
 * <p>The security framework maintains two distinct signing secrets as mandated by Phase 6
 * Decision #2:</p>
 * <ul>
 *   <li>{@link #ACCESS}  — corresponds to {@code security.jwt.access-secret}</li>
 *   <li>{@link #REFRESH} — corresponds to {@code security.jwt.refresh-secret}</li>
 * </ul>
 *
 * <p>Keeping these keys separate ensures that a compromised access-token signing key cannot
 * be used to forge refresh tokens, and prevents a refresh token from being accepted
 * as a valid bearer token for resource access. Any component that performs token validation
 * must explicitly select the appropriate {@code TokenKeyType} to avoid key-confusion attacks.</p>
 *
 * <h3>Usage Contract</h3>
 * <ul>
 *   <li>{@link JwtValidator#isValid(String, TokenKeyType)} — pass {@code ACCESS} when
 *       validating tokens extracted from the {@code Authorization: Bearer} header or
 *       the configured HttpOnly cookie.</li>
 *   <li>{@link JwtValidator#isValid(String, TokenKeyType)} — pass {@code REFRESH} when
 *       validating tokens submitted to the token-refresh endpoint.</li>
 * </ul>
 *
 * @see JwtValidator
 * @see JwtProvider
 * @since Phase 7.1
 */
public enum TokenKeyType {

    /**
     * Denotes the access-token signing key, configured via {@code security.jwt.access-secret}.
     *
     * <p>Access tokens are short-lived credentials (default 15 minutes) used to authenticate
     * individual API requests. They are transmitted as a bearer token in the
     * {@code Authorization} HTTP header, or via the HttpOnly cookie configured by
     * {@code security.jwt.cookie-name} when cookie-based transport is enabled.</p>
     */
    ACCESS,

    /**
     * Denotes the refresh-token signing key, configured via {@code security.jwt.refresh-secret}.
     *
     * <p>Refresh tokens are long-lived credentials (default 7 days) used exclusively to
     * obtain new access-token / refresh-token pairs from the token-refresh endpoint.
     * Refresh tokens must never be accepted as bearer tokens for resource access;
     * the {@link JwtValidator} enforces this constraint by requiring the caller to
     * specify the key type at validation time.</p>
     */
    REFRESH
}
