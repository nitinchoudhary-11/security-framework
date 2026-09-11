package com.dollop.app.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for Account Verification and Password Reset features.
 */
@ConfigurationProperties(prefix = "security.verification")
public class VerificationProperties {

    /**
     * Whether account verification features are active.
     */
    private boolean enabled = false;

    /**
     * Token expiration for password reset links in hours.
     */
    private int passwordResetTokenExpirationHours = 24;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getPasswordResetTokenExpirationHours() {
        return passwordResetTokenExpirationHours;
    }

    public void setPasswordResetTokenExpirationHours(int passwordResetTokenExpirationHours) {
        this.passwordResetTokenExpirationHours = passwordResetTokenExpirationHours;
    }
}
