package com.dollop.app.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Auto-configuration for One-Time Password capabilities.
 */
@AutoConfiguration
@EnableConfigurationProperties(OtpProperties.class)
@ConditionalOnProperty(prefix = "security.otp", name = "enabled", havingValue = "true")
public class OtpAutoConfiguration {

    // Beans for OtpGenerator and OtpStore defaults will be configured here.

}
