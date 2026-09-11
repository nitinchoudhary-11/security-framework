package com.dollop.app.user;

import java.util.Set;

/**
 * Unified contract representing an authenticated user across the framework.
 */
public interface SecurityPrincipal {

    /**
     * Unique identifier for the user (e.g., email, username, or UUID).
     *
     * @return the identifier
     */
    String getIdentifier();

    /**
     * The set of roles or authorities granted to this user.
     *
     * @return a set of authorities
     */
    Set<String> getAuthorities();

    /**
     * The source of the authentication.
     * Returns "LOCAL" for DB passwords, or "GOOGLE", "GITHUB", etc. for OAuth2.
     *
     * @return the authentication provider name
     */
    String getAuthProvider();

    /**
     * Determines if the user's account is currently locked due to too many failed attempts.
     *
     * @return true if locked
     */
    boolean isAccountLocked();

    /**
     * Determines if Multi-Factor Authentication is active for this user.
     *
     * @return true if MFA is required
     */
    boolean isMfaEnabled();
}
