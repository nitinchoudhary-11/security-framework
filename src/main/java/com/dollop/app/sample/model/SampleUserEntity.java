package com.dollop.app.sample.model;

import com.dollop.app.security.core.userdetails.SecurityPrincipalUserDetailsService;
import com.dollop.app.user.SecurityPrincipal;

import java.util.HashSet;
import java.util.Set;

/**
 * Sample domain user entity implementing SecurityPrincipal and PasswordHolder.
 */
public class SampleUserEntity implements SecurityPrincipal, SecurityPrincipalUserDetailsService.PasswordHolder {

    private final String id;
    private final String username;
    private final String encodedPassword;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final boolean locked;

    public SampleUserEntity(String id, String username, String encodedPassword, Set<String> roles, Set<String> permissions, boolean locked) {
        this.id = id;
        this.username = username;
        this.encodedPassword = encodedPassword;
        this.roles = roles;
        this.permissions = permissions;
        this.locked = locked;
    }

    @Override
    public String getIdentifier() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    @Override
    public Set<String> getAuthorities() {
        Set<String> authorities = new HashSet<>();
        roles.forEach(role -> authorities.add(role.startsWith("ROLE_") ? role : "ROLE_" + role));
        authorities.addAll(permissions);
        return authorities;
    }

    @Override
    public String getAuthProvider() {
        return "LOCAL";
    }

    @Override
    public boolean isAccountLocked() {
        return locked;
    }

    @Override
    public boolean isMfaEnabled() {
        return false;
    }

    @Override
    public String getEncodedPassword() {
        return encodedPassword;
    }
}

