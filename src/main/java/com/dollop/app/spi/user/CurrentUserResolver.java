package com.dollop.app.spi.user;

import com.dollop.app.user.SecurityPrincipal;

import java.util.Optional;

/**
 * Service Provider Interface for retrieving the active user context across different framework boundaries.
 */
public interface CurrentUserResolver {

    /**
     * Resolves the current principal.
     *
     * @return the current user if authenticated
     */
    Optional<SecurityPrincipal> resolveCurrentUser();
}
