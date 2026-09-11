package com.dollop.app.auth;

import com.dollop.app.user.SecurityPrincipal;

/**
 * Strategy for authenticating various types of credentials (e.g., username/password, OAuth2 tokens).
 *
 * @param <T> The type of credential this strategy supports.
 */
public interface AuthenticationStrategy<T> {

    /**
     * Determines if this strategy supports the given credential type.
     *
     * @param credentialType the class of the credential
     * @return true if supported
     */
    boolean supports(Class<?> credentialType);

    /**
     * Authenticates the given credentials and returns the fully populated SecurityPrincipal.
     *
     * @param credentials the raw credentials to authenticate
     * @return the authenticated principal
     */
    SecurityPrincipal authenticate(T credentials);
}
