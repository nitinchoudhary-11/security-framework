package com.dollop.app.spi.user;

import com.dollop.app.user.SecurityPrincipal;

import java.util.Optional;

/**
 * Service Provider Interface for locating user data from the consuming application's persistent storage.
 */
public interface UserLookupProvider {

    /**
     * Fetches a user principal by their unique identifier (e.g., username or email).
     *
     * @param identifier the lookup identifier
     * @return the SecurityPrincipal if found
     */
    Optional<SecurityPrincipal> findByIdentifier(String identifier);
}
