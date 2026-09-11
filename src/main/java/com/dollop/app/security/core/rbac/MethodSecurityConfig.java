package com.dollop.app.security.core.rbac;

import com.dollop.app.auth.ResourcePermissionEvaluator;
import com.dollop.app.auth.RoleHierarchyProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.util.Assert;

/**
 * Spring Security method-security configuration for the framework.
 *
 * <p>This configuration class activates Spring Security's annotation-based method security
 * and registers the custom expression handler that wires together:</p>
 * <ul>
 *   <li>{@link SpringRoleHierarchyAdapter} — expands directly assigned roles into
 *       their hierarchically reachable authorities via the {@link RoleHierarchyProvider} SPI.</li>
 *   <li>{@link FrameworkPermissionEvaluator} — evaluates object-level
 *       {@code hasPermission(...)} expressions via the {@link ResourcePermissionEvaluator} SPI.</li>
 * </ul>
 *
 * <h3>Supported Method Security Annotations</h3>
 * <p>With this configuration active, the following annotations are fully supported on
 * any Spring-managed bean in the consuming application:</p>
 * <ul>
 *   <li>{@code @PreAuthorize("hasRole('ADMIN')")} — checks that the principal holds the
 *       named role, with hierarchical expansion applied via {@link SpringRoleHierarchyAdapter}.</li>
 *   <li>{@code @PreAuthorize("hasAuthority('REPORTS_EXPORT')")} — checks for an exact
 *       authority string, with hierarchy expansion.</li>
 *   <li>{@code @PreAuthorize("hasPermission(#entity, 'write')")} — delegates to
 *       {@link FrameworkPermissionEvaluator} and then to {@link ResourcePermissionEvaluator}.</li>
 *   <li>{@code @PreAuthorize("hasPermission(#id, 'com.example.Report', 'export')")} —
 *       delegates to the ID+type form of {@link FrameworkPermissionEvaluator}.</li>
 *   <li>{@code @PostAuthorize}, {@code @PreFilter}, {@code @PostFilter} — supported via
 *       {@code @EnableMethodSecurity}; expression handler applies to all.</li>
 * </ul>
 *
 * <h3>{@code @EnableMethodSecurity} Note</h3>
 * <p>This class carries {@code @EnableMethodSecurity} to activate method-security processing.
 * The annotation is idempotent — if the consuming application also declares
 * {@code @EnableMethodSecurity}, Spring will log a warning about duplicate configuration
 * but will not fail startup. The framework's configuration takes precedence for the
 * {@link MethodSecurityExpressionHandler} bean because it is the first to register it.</p>
 *
 * <p>The {@code proxyTargetClass} attribute is left at its default value ({@code false})
 * to use JDK interface proxies where possible. Consuming applications that require
 * class-level proxying (CGLIB) due to concrete class injection should set
 * {@code @EnableMethodSecurity(proxyTargetClass = true)} in their own configuration.</p>
 *
 * <h3>Bean Registration</h3>
 * <p>This configuration is imported by {@code RbacAutoConfiguration}, which is conditional
 * on {@code security.rbac.enabled=true} (default). The expression handler bean is
 * registered as {@code methodSecurityExpressionHandler} — the name expected by Spring
 * Security's method-security infrastructure for override detection.</p>
 *
 * <h3>Customisation</h3>
 * <p>Consuming applications may replace any part of this configuration:</p>
 * <ul>
 *   <li>Provide a {@code @Bean RoleHierarchyProvider} to define custom hierarchy rules.</li>
 *   <li>Provide a {@code @Bean ResourcePermissionEvaluator} to implement object-level ACLs.</li>
 *   <li>Provide a {@code @Bean MethodSecurityExpressionHandler} to replace the entire
 *       expression handler (the framework's handler is then skipped via
 *       {@code @ConditionalOnMissingBean}).</li>
 * </ul>
 *
 * @see SpringRoleHierarchyAdapter
 * @see FrameworkPermissionEvaluator
 * @see RoleHierarchyProvider
 * @see ResourcePermissionEvaluator
 * @since Phase 7.3
 */
@Configuration(proxyBeanMethods = false)
@EnableMethodSecurity
public class MethodSecurityConfig {

    private final RoleHierarchyProvider roleHierarchyProvider;
    private final ResourcePermissionEvaluator resourcePermissionEvaluator;

    /**
     * Constructs the configuration with the required SPI dependencies.
     *
     * <p>Both dependencies are injected by Spring from the application context. The
     * consuming application provides its own implementations, or the framework's
     * auto-configured defaults are used:</p>
     * <ul>
     *   <li>{@link RoleHierarchyProvider} — default: flat (no hierarchy, returns input unchanged)</li>
     *   <li>{@link ResourcePermissionEvaluator} — default: deny-all (returns {@code false}
     *       for all permission requests)</li>
     * </ul>
     *
     * @param roleHierarchyProvider       the provider that defines authority expansion rules;
     *                                    must not be {@code null}
     * @param resourcePermissionEvaluator the evaluator that decides object-level permissions;
     *                                    must not be {@code null}
     * @throws IllegalArgumentException if either dependency is {@code null}
     */
    public MethodSecurityConfig(
            RoleHierarchyProvider roleHierarchyProvider,
            ResourcePermissionEvaluator resourcePermissionEvaluator) {

        Assert.notNull(roleHierarchyProvider,
                "roleHierarchyProvider must not be null");
        Assert.notNull(resourcePermissionEvaluator,
                "resourcePermissionEvaluator must not be null");

        this.roleHierarchyProvider = roleHierarchyProvider;
        this.resourcePermissionEvaluator = resourcePermissionEvaluator;
    }

    /**
     * Registers the {@link MethodSecurityExpressionHandler} that Spring Security uses
     * to evaluate SpEL expressions in method-security annotations.
     *
     * <p>The handler is configured with:</p>
     * <ul>
     *   <li>A {@link SpringRoleHierarchyAdapter} wrapping the {@link RoleHierarchyProvider}
     *       — enabling {@code hasRole()} and {@code hasAuthority()} to resolve hierarchically
     *       reachable authorities.</li>
     *   <li>A {@link FrameworkPermissionEvaluator} wrapping the
     *       {@link ResourcePermissionEvaluator} — enabling {@code hasPermission()} to
     *       delegate object-level access decisions to the consuming application's
     *       domain logic.</li>
     * </ul>
     *
     * <p>The bean is named {@code methodSecurityExpressionHandler} — the conventional name
     * that Spring Security's method-security post-processor searches for. Registering a
     * bean under this name is the supported, non-reflective way to replace the default
     * expression handler in Spring Security 6.</p>
     *
     * <h3>Role Prefix</h3>
     * <p>The expression handler's default role prefix is {@code "ROLE_"}, which means
     * {@code hasRole('ADMIN')} resolves to {@code hasAuthority('ROLE_ADMIN')}. This
     * is the Spring Security convention and is retained by default. Consuming applications
     * that store roles without the {@code "ROLE_"} prefix should either adjust their
     * stored authority strings or override the role prefix via a custom expression handler.</p>
     *
     * @return a fully configured {@link DefaultMethodSecurityExpressionHandler}; never
     *         {@code null}
     */
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        SpringRoleHierarchyAdapter roleHierarchyAdapter =
                new SpringRoleHierarchyAdapter(roleHierarchyProvider);

        FrameworkPermissionEvaluator permissionEvaluator =
                new FrameworkPermissionEvaluator(resourcePermissionEvaluator);

        DefaultMethodSecurityExpressionHandler handler =
                new DefaultMethodSecurityExpressionHandler();

        handler.setRoleHierarchy(roleHierarchyAdapter);
        handler.setPermissionEvaluator(permissionEvaluator);

        return handler;
    }
}
