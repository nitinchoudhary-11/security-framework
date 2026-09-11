package com.dollop.app.spi.auth;

import com.dollop.app.user.SecurityPrincipal;

/**
 * Service Provider Interface allowing customization of actions when access to a resource is denied.
 */
public interface AccessDeniedHandlerSpi {

    /**
     * Called when an authenticated user attempts to access a resource they lack authorization for.
     *
     * @param principal the authenticated user
     * @param resourcePath the URI or resource identifier that was blocked
     */
    void onAccessDenied(SecurityPrincipal principal, String resourcePath);
}
