package com.dollop.app.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for Role-Based Access Control logic.
 */
@ConfigurationProperties(prefix = "security.rbac")
public class RbacProperties {

    /**
     * Whether advanced RBAC evaluating is enabled.
     */
    private boolean enabled = true;

    /**
     * Whether to strictly throw exceptions when an unknown permission is requested.
     */
    private boolean strictMode = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isStrictMode() {
        return strictMode;
    }

    public void setStrictMode(boolean strictMode) {
        this.strictMode = strictMode;
    }
}
