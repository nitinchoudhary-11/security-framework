package com.dollop.app.test;

import com.dollop.app.auth.ResourcePermissionEvaluator;
import com.dollop.app.auth.RoleHierarchyProvider;
import com.dollop.app.spi.user.UserLookupProvider;
import com.dollop.app.user.SecurityPrincipal;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

/**
 * Test configuration providing mock SPI implementations and test endpoints.
 */
@TestConfiguration
public class TestSecurityConfig {

    public static class TestUser implements SecurityPrincipal {
        private final String identifier;
        private final Set<String> roles;
        private final Set<String> permissions;
        private final boolean locked;

        public TestUser(String identifier, Set<String> roles, Set<String> permissions, boolean locked) {
            this.identifier = identifier;
            this.roles = roles;
            this.permissions = permissions;
            this.locked = locked;
        }

        @Override
        public String getIdentifier() { return identifier; }
        public String getUsername() { return identifier; }
        public Set<String> getRoles() { return roles; }
        public Set<String> getPermissions() { return permissions; }
        @Override
        public Set<String> getAuthorities() {
            Set<String> auths = new HashSet<>();
            roles.forEach(r -> auths.add(r.startsWith("ROLE_") ? r : "ROLE_" + r));
            auths.addAll(permissions);
            return auths;
        }
        @Override
        public String getAuthProvider() { return "TEST"; }
        @Override
        public boolean isAccountLocked() { return locked; }
        @Override
        public boolean isMfaEnabled() { return false; }
    }

    @Bean
    @Primary
    public UserLookupProvider testUserLookupProvider() {
        Map<String, TestUser> users = new HashMap<>();
        users.put("john", new TestUser("john", Set.of("USER"), Set.of("READ_DOCS"), false));
        users.put("admin", new TestUser("admin", Set.of("ADMIN"), Set.of("WRITE_DOCS", "READ_DOCS"), false));
        users.put("locked_user", new TestUser("locked_user", Set.of("USER"), Set.of(), true));

        return identifier -> Optional.ofNullable(users.get(identifier));
    }

    @Bean
    @Primary
    public RoleHierarchyProvider testRoleHierarchyProvider() {
        return authorities -> {
            Set<String> expanded = new HashSet<>(authorities);
            if (authorities.contains("ROLE_ADMIN") || authorities.contains("ADMIN")) {
                expanded.add("ROLE_MODERATOR");
                expanded.add("ROLE_USER");
                expanded.add("READ_DOCS");
                expanded.add("WRITE_DOCS");
            }
            if (authorities.contains("ROLE_MODERATOR") || authorities.contains("MODERATOR")) {
                expanded.add("ROLE_USER");
                expanded.add("READ_DOCS");
            }
            return expanded;
        };
    }

    @Bean
    @Primary
    public ResourcePermissionEvaluator testResourcePermissionEvaluator() {
        return (principal, targetResource, permission) -> {
            if ("document".equals(targetResource) && "read".equals(permission)) {
                return principal.getAuthorities().contains("READ_DOCS")
                        || principal.getAuthorities().contains("ROLE_ADMIN");
            }
            if ("document".equals(targetResource) && "write".equals(permission)) {
                return principal.getAuthorities().contains("WRITE_DOCS")
                        || principal.getAuthorities().contains("ROLE_ADMIN");
            }
            return false;
        };
    }

    @RestController
    @RequestMapping("/api/test")
    public static class TestMethodSecurityController {

        @GetMapping("/public/ping")
        public String publicPing() {
            return "pong";
        }

        @GetMapping("/protected/me")
        public String protectedMe() {
            return "authenticated";
        }

        @GetMapping("/admin-only")
        @PreAuthorize("hasRole('ADMIN')")
        public String adminOnly() {
            return "admin-content";
        }

        @GetMapping("/user-only")
        @PreAuthorize("hasRole('USER')")
        public String userOnly() {
            return "user-content";
        }

        @GetMapping("/authority-check")
        @PreAuthorize("hasAuthority('WRITE_DOCS')")
        public String authorityCheck() {
            return "authority-granted";
        }

        @GetMapping("/permission-read")
        @PreAuthorize("hasPermission('document', 'read')")
        public String permissionRead() {
            return "permission-read-granted";
        }

        @GetMapping("/permission-write")
        @PreAuthorize("hasPermission('document', 'write')")
        public String permissionWrite() {
            return "permission-write-granted";
        }
    }
}
