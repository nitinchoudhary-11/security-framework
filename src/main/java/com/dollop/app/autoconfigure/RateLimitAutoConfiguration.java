package com.dollop.app.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Auto-configuration for Rate Limiting features.
 */
@AutoConfiguration
@EnableConfigurationProperties(RateLimitProperties.class)
@ConditionalOnProperty(prefix = "security.rate-limit", name = "enabled", havingValue = "true")
public class RateLimitAutoConfiguration {

    // Beans for RateLimit interception and storage will be configured here.

}
