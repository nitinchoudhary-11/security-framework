package com.dollop.app.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Auto-configuration for Security Event Auditing.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuditProperties.class)
@ConditionalOnProperty(prefix = "security.audit", name = "enabled", matchIfMissing = true)
public class AuditAutoConfiguration {

    // Default AuditEventListener beans will be configured here.

}
