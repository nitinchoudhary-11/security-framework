package com.dollop.app.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for standard One-Time Passwords.
 */
@ConfigurationProperties(prefix = "security.otp")
public class OtpProperties {

    /**
     * Whether OTP features are enabled.
     */
    private boolean enabled = false;

    /**
     * The length of the generated OTP.
     */
    private int length = 6;

    /**
     * Expiration time for OTPs in seconds.
     */
    private int expirationSeconds = 300;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public int getExpirationSeconds() {
        return expirationSeconds;
    }

    public void setExpirationSeconds(int expirationSeconds) {
        this.expirationSeconds = expirationSeconds;
    }
}
