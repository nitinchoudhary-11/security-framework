package com.dollop.app.autoconfigure;

import com.dollop.app.auth.ResourcePermissionEvaluator;
import com.dollop.app.auth.RoleHierarchyProvider;
import com.dollop.app.security.core.rbac.MethodSecurityConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.util.Collections;

/**
 * Auto-configuration for Role-Based Access Control (RBAC) and Method Security.
 *
 * <p>Activated when {@code security.rbac.enabled} is {@code true} (default).
 * Imports {@link MethodSecurityConfig} to register Spring Security's
 * {@code MethodSecurityExpressionHandler} and provides default fallback SPI implementations
 * for {@link RoleHierarchyProvider} and {@link ResourcePermissionEvaluator}.</p>
 *
 * @see MethodSecurityConfig
 * @see RoleHierarchyProvider
 * @see ResourcePermissionEvaluator
 * @since Phase 7.6
 */
@AutoConfiguration
@Import(MethodSecurityConfig.class)
@EnableConfigurationProperties(RbacProperties.class)
@ConditionalOnProperty(prefix = "security.rbac", name = "enabled", matchIfMissing = true)
public class RbacAutoConfiguration {

    /**
     * Fallback {@link RoleHierarchyProvider} bean registered when no custom provider is defined.
     *
     * <p>Provides a flat (no hierarchy) pass-through resolution where the input authorities
     * are returned without expansion.</p>
     *
     * @return a pass-through {@link RoleHierarchyProvider}
     */
    @Bean
    @ConditionalOnMissingBean(RoleHierarchyProvider.class)
    public RoleHierarchyProvider roleHierarchyProvider() {
        return authorities -> (authorities != null) ? authorities : Collections.emptySet();
    }

    /**
     * Fallback {@link ResourcePermissionEvaluator} bean registered when no custom evaluator is defined.
     *
     * <p>Provides a safe deny-all default implementation returning {@code false} for all
     * {@code hasPermission(...)} evaluation checks.</p>
     *
     * @return a deny-all {@link ResourcePermissionEvaluator}
     */
    @Bean
    @ConditionalOnMissingBean(ResourcePermissionEvaluator.class)
    public ResourcePermissionEvaluator resourcePermissionEvaluator() {
        return (principal, targetResource, permission) -> false;
    }
}
