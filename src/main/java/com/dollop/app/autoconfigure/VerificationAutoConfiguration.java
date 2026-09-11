package com.dollop.app.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Auto-configuration for Identity Verification and Password Reset.
 */
@AutoConfiguration
@EnableConfigurationProperties(VerificationProperties.class)
@ConditionalOnProperty(prefix = "security.verification", name = "enabled", havingValue = "true")
public class VerificationAutoConfiguration {

    // Beans for PasswordResetManager and Verification flow will be configured here.

}
