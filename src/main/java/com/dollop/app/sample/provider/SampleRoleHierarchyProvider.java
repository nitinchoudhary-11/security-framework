package com.dollop.app.sample.provider;

import com.dollop.app.auth.RoleHierarchyProvider;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Sample implementation of RoleHierarchyProvider SPI defining role inheritance rules.
 */
@Component
public class SampleRoleHierarchyProvider implements RoleHierarchyProvider {

    @Override
    public Set<String> getReachableAuthorities(Set<String> authorities) {
        Set<String> expanded = new HashSet<>(authorities);

        if (authorities.contains("ROLE_ADMIN") || authorities.contains("ADMIN")) {
            expanded.add("ROLE_MANAGER");
            expanded.add("ROLE_USER");
        }
        if (authorities.contains("ROLE_MANAGER") || authorities.contains("MANAGER")) {
            expanded.add("ROLE_USER");
        }

        return expanded;
    }
}
