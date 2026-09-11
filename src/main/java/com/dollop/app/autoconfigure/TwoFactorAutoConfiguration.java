package com.dollop.app.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Auto-configuration for Two-Factor Authentication via Authenticator Apps.
 */
@AutoConfiguration
@EnableConfigurationProperties(TwoFactorProperties.class)
@ConditionalOnProperty(prefix = "security.two-factor", name = "enabled", havingValue = "true")
public class TwoFactorAutoConfiguration {

    // Beans for TotpManager will be configured here.

}
