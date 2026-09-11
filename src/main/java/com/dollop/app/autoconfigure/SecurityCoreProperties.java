package com.dollop.app.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.ArrayList;
import java.util.List;

/**
 * Core security framework configurations.
 */
@ConfigurationProperties(prefix = "security.core")
public class SecurityCoreProperties {

    /**
     * Whether the security framework auto-configuration is completely enabled.
     */
    private boolean enabled = true;

    /**
     * List of endpoints that are completely public (bypass authentication).
     */
    private List<String> publicUrls = new ArrayList<>();

    /**
     * BCrypt password encoder strength (rounds). Default = 12 (Phase 6 Decision #3).
     */
    private int bcryptStrength = 12;

    /**
     * List of allowed CORS origins. Default is empty (no wildcard '*').
     */
    private List<String> allowedOrigins = new ArrayList<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getPublicUrls() {
        return publicUrls;
    }

    public void setPublicUrls(List<String> publicUrls) {
        this.publicUrls = publicUrls;
    }

    public int getBcryptStrength() {
        return bcryptStrength;
    }

    public void setBcryptStrength(int bcryptStrength) {
        this.bcryptStrength = bcryptStrength;
    }

    public List<String> getAllowedOrigins() {
        return allowedOrigins;
    }

    public void setAllowedOrigins(List<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }
}

