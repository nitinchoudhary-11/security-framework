package com.dollop.app.auth;

import com.dollop.app.user.SecurityPrincipal;
import java.util.Optional;

/**
 * Decouples the retrieval of the current user from the underlying framework (e.g., Spring SecurityContextHolder).
 */
public interface CurrentUserProvider {

    /**
     * Retrieves the currently authenticated principal if available.
     *
     * @return an Optional containing the principal, or empty if not authenticated
     */
    Optional<SecurityPrincipal> getCurrentUser();

    /**
     * Retrieves the currently authenticated principal, throwing an exception if none exists.
     *
     * @return the authenticated principal
     */
    SecurityPrincipal getCurrentUserOrThrow();
}
