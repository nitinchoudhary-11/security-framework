package com.dollop.app.security.core.rbac;

import com.dollop.app.auth.RoleHierarchyProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Spring Security {@link RoleHierarchy} implementation that adapts the framework's
 * {@link RoleHierarchyProvider} SPI into the Spring Security role-hierarchy contract.
 *
 * <p>Spring Security's method-security SpEL expressions such as
 * {@code @PreAuthorize("hasRole('ADMIN')")} use the configured {@link RoleHierarchy}
 * to expand a principal's directly assigned roles into the full set of reachable
 * authorities. This class bridges the framework's {@link RoleHierarchyProvider} SPI
 * — which the consuming application implements — with the Spring Security infrastructure
 * that {@code DefaultMethodSecurityExpressionHandler} and
 * {@code FilterSecurityInterceptor} expect.</p>
 *
 * <h3>Role Expansion Example</h3>
 * <p>Given a hierarchy configured as {@code ROLE_ADMIN > ROLE_USER > ROLE_VIEWER},
 * a principal with directly assigned role {@code ROLE_ADMIN} will have the following
 * reachable authorities after expansion:</p>
 * <pre>{@code
 * Input:    { "ROLE_ADMIN" }
 * Expanded: { "ROLE_ADMIN", "ROLE_USER", "ROLE_VIEWER" }
 * }</pre>
 * <p>This means {@code @PreAuthorize("hasRole('USER')")} grants access to a principal
 * with {@code ROLE_ADMIN}, even if {@code ROLE_USER} is not directly assigned.</p>
 *
 * <h3>Delegation to SPI</h3>
 * <p>All authority expansion logic is delegated to
 * {@link RoleHierarchyProvider#getReachableAuthorities(Set)}, which the consuming
 * application implements. The consuming application controls the full hierarchy
 * definition — it may be loaded from a database, a configuration file, or defined
 * statically in code. The framework makes no assumption about the hierarchy structure.</p>
 *
 * <h3>Input Handling</h3>
 * <p>{@link #getReachableGrantedAuthorities(Collection)} accepts any
 * {@code Collection<? extends GrantedAuthority>}. The authority strings are extracted,
 * passed to the {@link RoleHierarchyProvider}, and the expanded set is converted back
 * to {@link GrantedAuthority} instances. Null or empty inputs return an empty collection.</p>
 *
 * <h3>Default Behaviour (No Custom SPI)</h3>
 * <p>The framework registers a {@code DefaultRoleHierarchyProvider} when no custom
 * {@link RoleHierarchyProvider} bean is present. The default implementation returns
 * the input authorities unchanged — i.e., no hierarchy is applied. This is a safe
 * default: all role checks work based on exact role assignment, with no implicit
 * role inheritance.</p>
 *
 * <h3>Bean Registration</h3>
 * <p>This class is instantiated by {@code MethodSecurityConfig} (same Phase 7.3) and
 * injected into {@code DefaultMethodSecurityExpressionHandler} via
 * {@code setRoleHierarchy(...)}. It is not registered as a named Spring bean directly;
 * the {@code MethodSecurityConfig} holds the reference.</p>
 *
 * <h3>Thread Safety</h3>
 * <p>This class is stateless after construction. Concurrent authority-expansion calls
 * are safe as long as the injected {@link RoleHierarchyProvider} is also thread-safe.</p>
 *
 * @see RoleHierarchyProvider
 * @see MethodSecurityConfig
 * @see org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
 * @since Phase 7.3
 */
@Slf4j
public class SpringRoleHierarchyAdapter implements RoleHierarchy {

    private final RoleHierarchyProvider roleHierarchyProvider;

    /**
     * Constructs the adapter with the required {@link RoleHierarchyProvider} delegate.
     *
     * @param roleHierarchyProvider the SPI implementation that defines the authority
     *                              expansion rules; must not be {@code null}
     * @throws IllegalArgumentException if {@code roleHierarchyProvider} is {@code null}
     */
    public SpringRoleHierarchyAdapter(RoleHierarchyProvider roleHierarchyProvider) {
        Assert.notNull(roleHierarchyProvider, "roleHierarchyProvider must not be null");
        this.roleHierarchyProvider = roleHierarchyProvider;
    }

    /**
     * Returns the full set of authorities reachable by the principal from their directly
     * assigned authorities, applying hierarchical expansion via the
     * {@link RoleHierarchyProvider} SPI.
     *
     * <p>The expansion flow is:</p>
     * <ol>
     *   <li>Extract the authority strings from the input {@link GrantedAuthority} collection.</li>
     *   <li>Pass the raw authority set to
     *       {@link RoleHierarchyProvider#getReachableAuthorities(Set)}.</li>
     *   <li>Wrap the expanded authority strings in {@link SimpleGrantedAuthority} instances.</li>
     *   <li>Return the expanded collection.</li>
     * </ol>
     *
     * <p>If the input collection is {@code null} or empty, an empty, unmodifiable collection
     * is returned immediately without invoking the provider.</p>
     *
     * <p>Null or blank authority strings within the input collection are filtered out
     * before delegation to prevent potential {@link NullPointerException} in the provider.
     * The same filter is applied to the expanded set returned by the provider.</p>
     *
     * @param authorities the collection of directly assigned authorities from the
     *                    principal's {@link org.springframework.security.core.Authentication};
     *                    may be {@code null} or empty
     * @return an unmodifiable, non-null collection of all reachable
     *         {@link GrantedAuthority} instances after hierarchy expansion; never contains
     *         {@code null} or blank entries
     */
    @Override
    public Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(
            Collection<? extends GrantedAuthority> authorities) {

        if (authorities == null || authorities.isEmpty()) {
            return Collections.emptyList();
        }

        Set<String> directAuthorityStrings = authorities.stream()
                .filter(a -> a != null && a.getAuthority() != null
                        && !a.getAuthority().isBlank())
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        if (directAuthorityStrings.isEmpty()) {
            return Collections.emptyList();
        }

        Set<String> reachableAuthorityStrings;
        try {
            reachableAuthorityStrings = roleHierarchyProvider
                    .getReachableAuthorities(directAuthorityStrings);
        } catch (Exception ex) {
            log.warn("RoleHierarchyProvider threw an exception during authority expansion " +
                    "for authorities {}. Falling back to direct authorities only.",
                    directAuthorityStrings, ex);
            reachableAuthorityStrings = directAuthorityStrings;
        }

        if (reachableAuthorityStrings == null || reachableAuthorityStrings.isEmpty()) {
            return Collections.emptyList();
        }

        Set<GrantedAuthority> reachableGrantedAuthorities = reachableAuthorityStrings.stream()
                .filter(a -> a != null && !a.isBlank())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toUnmodifiableSet());

        log.debug("Role hierarchy expansion: direct=[{}], reachable=[{}]",
                directAuthorityStrings, reachableAuthorityStrings);

        return reachableGrantedAuthorities;
    }
}
