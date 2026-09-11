package com.dollop.app.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for Authenticator Apps and 2FA features.
 */
@ConfigurationProperties(prefix = "security.two-factor")
public class TwoFactorProperties {

    /**
     * Whether TOTP 2FA features are enabled.
     */
    private boolean enabled = false;

    /**
     * The issuer name displayed in the Authenticator App.
     */
    private String issuerName = "Security App";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }
}
