package com.dollop.app.auth;

import java.util.Set;

/**
 * Provides hierarchical role resolution to support role inheritance (e.g., ADMIN implies USER).
 */
public interface RoleHierarchyProvider {

    /**
     * Returns the full set of reachable authorities including those granted implicitly via hierarchy.
     *
     * @param authorities the base authorities directly assigned to the user
     * @return the expanded set of authorities
     */
    Set<String> getReachableAuthorities(Set<String> authorities);
}
