package com.dollop.app.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for Brute-force protection and Rate Limiting.
 */
@ConfigurationProperties(prefix = "security.rate-limit")
public class RateLimitProperties {

    /**
     * Whether rate limiting is active.
     */
    private boolean enabled = false;

    /**
     * Maximum requests allowed per IP in a given window.
     */
    private int maxRequestsPerIp = 100;

    /**
     * The time window for the rate limit in seconds.
     */
    private int windowSeconds = 60;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getMaxRequestsPerIp() {
        return maxRequestsPerIp;
    }

    public void setMaxRequestsPerIp(int maxRequestsPerIp) {
        this.maxRequestsPerIp = maxRequestsPerIp;
    }

    public int getWindowSeconds() {
        return windowSeconds;
    }

    public void setWindowSeconds(int windowSeconds) {
        this.windowSeconds = windowSeconds;
    }
}
