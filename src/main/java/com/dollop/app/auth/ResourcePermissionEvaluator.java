package com.dollop.app.auth;

import com.dollop.app.user.SecurityPrincipal;

/**
 * Evaluates whether a principal has a specific permission on a target resource domain object.
 */
public interface ResourcePermissionEvaluator {

    /**
     * Checks if the principal has the specified permission on the target resource.
     *
     * @param principal the authenticated user
     * @param targetResource the domain object being accessed
     * @param permission the action requested (e.g., "read", "write")
     * @return true if access is granted, false otherwise
     */
    boolean hasPermission(SecurityPrincipal principal, Object targetResource, String permission);
}
