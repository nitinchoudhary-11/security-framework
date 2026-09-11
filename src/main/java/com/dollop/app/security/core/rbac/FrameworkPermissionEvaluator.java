package com.dollop.app.security.core.rbac;

import com.dollop.app.auth.ResourcePermissionEvaluator;
import com.dollop.app.security.core.userdetails.SecurityPrincipalUserDetails;
import com.dollop.app.user.SecurityPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * Spring Security {@link PermissionEvaluator} implementation that delegates
 * object-level permission evaluation to the framework's {@link ResourcePermissionEvaluator} SPI.
 *
 * <p>This class enables the {@code @PreAuthorize("hasPermission(#entity, 'write')")} and
 * {@code @PreAuthorize("hasPermission(#id, 'com.example.Document', 'read')")} SpEL
 * expressions in Spring Security's method-security layer. It bridges Spring Security's
 * {@link PermissionEvaluator} contract — which operates on Spring Security's
 * {@link Authentication} objects — with the framework's {@link ResourcePermissionEvaluator}
 * SPI — which operates on the domain's {@link SecurityPrincipal}.</p>
 *
 * <h3>Supported SpEL Expressions</h3>
 * <ul>
 *   <li>{@code @PreAuthorize("hasPermission(#domainObject, 'read')")} — evaluates
 *       {@link #hasPermission(Authentication, Object, Object)} against a loaded domain object.</li>
 *   <li>{@code @PreAuthorize("hasPermission(#id, 'com.example.Report', 'export')")} — evaluates
 *       {@link #hasPermission(Authentication, Serializable, String, Object)} against a
 *       target ID and type. The consuming application's {@link ResourcePermissionEvaluator}
 *       is responsible for loading the domain object by ID if required.</li>
 * </ul>
 *
 * <h3>Principal Resolution</h3>
 * <p>Both {@code hasPermission} methods extract the {@link SecurityPrincipal} from the
 * {@link Authentication#getPrincipal()} object. This requires the principal stored in
 * the {@link Authentication} object to be a {@link SecurityPrincipalUserDetails} instance
 * — which is guaranteed when authentication flows through the framework's
 * {@code AuthenticationProviderAdapter} and JWT authentication filter.</p>
 *
 * <p>If the principal is not a {@link SecurityPrincipalUserDetails} instance (e.g., in
 * tests or when using a non-framework authentication provider), permission evaluation
 * returns {@code false} to fail safely.</p>
 *
 * <h3>SPI Delegation</h3>
 * <p>All permission decisions are delegated to {@link ResourcePermissionEvaluator#hasPermission(
 * SecurityPrincipal, Object, String)}. The consuming application provides its own
 * implementation of this SPI — registered as a {@code @Bean} — to encode the actual
 * business rules for object-level access control.</p>
 *
 * <h3>Default (No SPI) Behaviour</h3>
 * <p>If the consuming application does not provide a {@link ResourcePermissionEvaluator}
 * bean, the framework registers a {@code DefaultResourcePermissionEvaluator} that denies
 * all object-level permissions (returns {@code false}). This is a safe default: no
 * unintended access is granted. Consuming applications that use
 * {@code @PreAuthorize("hasPermission(...)")} must provide their own evaluator.</p>
 *
 * <h3>Bean Registration</h3>
 * <p>This class is instantiated and registered by {@code MethodSecurityConfig}
 * (same Phase 7.3), which injects it into
 * {@code DefaultMethodSecurityExpressionHandler} via
 * {@code setPermissionEvaluator(...)}.</p>
 *
 * <h3>Thread Safety</h3>
 * <p>This class is stateless and thread-safe. All state is in the injected
 * {@link ResourcePermissionEvaluator} implementation, which must also be thread-safe.</p>
 *
 * @see ResourcePermissionEvaluator
 * @see MethodSecurityConfig
 * @since Phase 7.3
 */
@Slf4j
public class FrameworkPermissionEvaluator implements PermissionEvaluator {

    private final ResourcePermissionEvaluator resourcePermissionEvaluator;

    /**
     * Constructs the evaluator with the required SPI delegate.
     *
     * @param resourcePermissionEvaluator the domain-level permission evaluator provided
     *                                    by the consuming application (or the framework's
     *                                    deny-all default); must not be {@code null}
     * @throws IllegalArgumentException if {@code resourcePermissionEvaluator} is {@code null}
     */
    public FrameworkPermissionEvaluator(ResourcePermissionEvaluator resourcePermissionEvaluator) {
        Assert.notNull(resourcePermissionEvaluator,
                "resourcePermissionEvaluator must not be null");
        this.resourcePermissionEvaluator = resourcePermissionEvaluator;
    }

    /**
     * Evaluates whether the currently authenticated principal has the specified permission
     * on the given domain object.
     *
     * <p>This method is invoked by Spring Security's SpEL engine when evaluating
     * {@code @PreAuthorize("hasPermission(#domainObject, 'permissionType')")} expressions.
     * The {@code targetDomainObject} is the resolved value of the annotated parameter
     * (e.g., a loaded JPA entity or DTO).</p>
     *
     * <p>The permission type is expected as a {@code String} in the {@code permission}
     * argument. Spring Security passes it as an {@code Object}; this method safely
     * casts it. If the permission value is not a {@code String}, or if it is {@code null},
     * the evaluation returns {@code false}.</p>
     *
     * <p>If the authentication is anonymous, unauthenticated, or its principal is not
     * a {@link SecurityPrincipalUserDetails}, evaluation returns {@code false} to
     * fail safely without propagating an exception.</p>
     *
     * @param authentication     the current security context's authentication object;
     *                           may be {@code null} for anonymous access attempts
     * @param targetDomainObject the domain object being accessed; may be {@code null}
     *                           (in which case the SPI evaluator decides the outcome)
     * @param permission         the action being requested (e.g., {@code "read"},
     *                           {@code "write"}, {@code "delete"}); expected to be a
     *                           {@code String}
     * @return {@code true} if the principal is granted the specified permission on the
     *         domain object; {@code false} otherwise or on any resolution failure
     */
    @Override
    public boolean hasPermission(
            Authentication authentication,
            Object targetDomainObject,
            Object permission) {

        SecurityPrincipal principal = resolvePrincipal(authentication);
        if (principal == null) {
            log.debug("hasPermission(object) — could not resolve SecurityPrincipal from " +
                    "Authentication; denying access");
            return false;
        }

        String permissionString = resolvePermissionString(permission);
        if (permissionString == null) {
            log.debug("hasPermission(object) — permission argument is null or not a String; " +
                    "denying access for principal [{}]", principal.getIdentifier());
            return false;
        }

        boolean granted = resourcePermissionEvaluator.hasPermission(
                principal, targetDomainObject, permissionString);

        log.debug("hasPermission(object) — principal [{}], targetType [{}], permission [{}]: {}",
                principal.getIdentifier(),
                targetDomainObject != null ? targetDomainObject.getClass().getSimpleName() : "null",
                permissionString,
                granted ? "GRANTED" : "DENIED");

        return granted;
    }

    /**
     * Evaluates whether the currently authenticated principal has the specified permission
     * on the domain object identified by the given ID and type.
     *
     * <p>This method is invoked by Spring Security's SpEL engine when evaluating
     * {@code @PreAuthorize("hasPermission(#id, 'com.example.Document', 'write')")} expressions.
     * The {@code targetId} is the serializable identifier of the target object, and
     * {@code targetType} is its fully qualified class name (as a {@code String}).</p>
     *
     * <p>The framework wraps the {@code targetId} and {@code targetType} into a
     * {@link TargetReference} value object and passes it to
     * {@link ResourcePermissionEvaluator#hasPermission(SecurityPrincipal, Object, String)}.
     * The consuming application's evaluator is responsible for loading the domain object
     * by ID when required for the permission decision.</p>
     *
     * <p>If any parameter cannot be resolved (null permission, non-{@code String} permission,
     * or missing principal), the evaluation returns {@code false}.</p>
     *
     * @param authentication the current security context's authentication object;
     *                       may be {@code null} for anonymous access attempts
     * @param targetId       the serializable identifier of the target domain object
     * @param targetType     the fully qualified class name of the target domain object;
     *                       provided as an {@code Object} by Spring Security, expected
     *                       to be a {@code String}
     * @param permission     the action being requested; expected to be a {@code String}
     * @return {@code true} if the principal is granted the specified permission on the
     *         identified domain object; {@code false} otherwise or on any resolution failure
     */
    @Override
    public boolean hasPermission(
            Authentication authentication,
            Serializable targetId,
            String targetType,
            Object permission) {

        SecurityPrincipal principal = resolvePrincipal(authentication);
        if (principal == null) {
            log.debug("hasPermission(id, type) — could not resolve SecurityPrincipal from " +
                    "Authentication; denying access");
            return false;
        }

        String permissionString = resolvePermissionString(permission);
        if (permissionString == null) {
            log.debug("hasPermission(id, type) — permission argument is null or not a String; " +
                    "denying access for principal [{}]", principal.getIdentifier());
            return false;
        }

        TargetReference targetReference = new TargetReference(targetId, targetType);

        boolean granted = resourcePermissionEvaluator.hasPermission(
                principal, targetReference, permissionString);

        log.debug("hasPermission(id, type) — principal [{}], targetType [{}], targetId [{}], " +
                "permission [{}]: {}",
                principal.getIdentifier(),
                targetType,
                targetId,
                permissionString,
                granted ? "GRANTED" : "DENIED");

        return granted;
    }

    /**
     * Extracts the {@link SecurityPrincipal} from the Spring Security {@link Authentication}
     * object.
     *
     * <p>The principal within the {@link Authentication} must be an instance of
     * {@link SecurityPrincipalUserDetails} — this is guaranteed when the framework's
     * {@code AuthenticationProviderAdapter} or JWT authentication filter was used to
     * authenticate the request. If the principal is of a different type (e.g., during
     * tests or when using a third-party authentication provider), this method returns
     * {@code null} and the caller denies access safely.</p>
     *
     * @param authentication the Spring Security authentication object; may be {@code null}
     * @return the resolved {@link SecurityPrincipal}, or {@code null} if it cannot be
     *         extracted
     */
    private SecurityPrincipal resolvePrincipal(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        Object rawPrincipal = authentication.getPrincipal();
        if (rawPrincipal instanceof SecurityPrincipalUserDetails userDetails) {
            return userDetails.getPrincipal();
        }
        return null;
    }

    /**
     * Safely casts the raw {@code permission} argument to a {@code String}.
     *
     * <p>Spring Security's {@link PermissionEvaluator} contract declares {@code permission}
     * as {@code Object} to allow flexibility. This framework enforces {@code String} as the
     * only supported permission type. Non-{@code String} or {@code null} values cause the
     * evaluator to return {@code false}.</p>
     *
     * @param permission the raw permission argument from the SpEL expression
     * @return the permission as a {@code String}, or {@code null} if not applicable
     */
    private String resolvePermissionString(Object permission) {
        if (permission instanceof String permString && !permString.isBlank()) {
            return permString;
        }
        return null;
    }

    /**
     * Immutable value object passed to {@link ResourcePermissionEvaluator} when
     * {@link #hasPermission(Authentication, Serializable, String, Object)} is called.
     *
     * <p>The consuming application's {@link ResourcePermissionEvaluator} implementation
     * receives this as the {@code targetResource} argument when the caller uses
     * the {@code (id, type, permission)} form of {@code hasPermission}. The evaluator
     * may use the {@code targetId} and {@code targetType} to load the domain object
     * from its persistence layer before making the permission decision.</p>
     *
     * @param targetId   the serializable identifier of the domain object
     * @param targetType the fully qualified class name of the domain object type
     */
    public record TargetReference(Serializable targetId, String targetType) {}
}
