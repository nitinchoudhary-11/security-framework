package com.dollop.app.security.core.userdetails;

import com.dollop.app.spi.user.UserLookupProvider;
import com.dollop.app.user.SecurityPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * Spring Security {@link UserDetailsService} implementation that delegates user lookup
 * to the framework's {@link UserLookupProvider} SPI.
 *
 * <p>Spring Security's {@code DaoAuthenticationProvider} requires a {@link UserDetailsService}
 * to load user data during the authentication process. This implementation bridges the
 * gap between Spring Security's lookup contract and the framework's {@link UserLookupProvider}
 * SPI, which is implemented by the consuming application against its own persistence layer.</p>
 *
 * <h3>Lookup Flow</h3>
 * <ol>
 *   <li>{@code DaoAuthenticationProvider} calls {@link #loadUserByUsername(String)} with
 *       the submitted identifier (email, username, etc.).</li>
 *   <li>This service delegates to {@link UserLookupProvider#findByIdentifier(String)}.</li>
 *   <li>If found, the {@link SecurityPrincipal} is wrapped in a
 *       {@link SecurityPrincipalUserDetails} adapter.</li>
 *   <li>The adapter is returned to {@code DaoAuthenticationProvider}, which then performs
 *       BCrypt password verification against the encoded password.</li>
 * </ol>
 *
 * <h3>Encoded Password Requirement</h3>
 * <p>This service expects the consuming application's {@link SecurityPrincipal}
 * implementation to carry the encoded password. The encoded password is passed to
 * {@link SecurityPrincipalUserDetails} for credential verification by
 * {@code DaoAuthenticationProvider}. If the {@link SecurityPrincipal} implementation
 * does not carry a password (e.g., for OAuth2-only accounts), the consuming application
 * must provide a sentinel value that will never match any BCrypt hash (e.g., an empty
 * string or a randomly generated, non-BCrypt string).</p>
 *
 * <p>To access the encoded password, this service requires the loaded
 * {@link SecurityPrincipal} to implement the {@code PasswordHolder} sub-interface.
 * If the principal does not implement this interface, a sentinel empty string is used
 * and an appropriate debug log is emitted.</p>
 *
 * <h3>Account Lock Handling</h3>
 * <p>This service does not enforce account-lock state directly. The lock state is
 * communicated to Spring Security through {@link SecurityPrincipalUserDetails#isAccountNonLocked()},
 * which maps {@link SecurityPrincipal#isAccountLocked()} to the Spring Security contract.
 * {@code DaoAuthenticationProvider} then throws {@code LockedException} as appropriate,
 * which is translated to HTTP 423 or HTTP 401 by the framework's entry point per
 * Phase 6 Decision #10.</p>
 *
 * <h3>Security Logging</h3>
 * <p>When a user is not found, this service throws {@link UsernameNotFoundException}
 * with a generic message that does not reveal whether the identifier exists in the
 * system. This prevents user-enumeration attacks. Debug-level logging uses the full
 * identifier, but this is only emitted when DEBUG log level is explicitly configured
 * by the consuming application.</p>
 *
 * <h3>Bean Registration</h3>
 * <p>This service is registered in {@code SecurityCoreAutoConfiguration} under
 * {@code @ConditionalOnMissingBean(UserDetailsService.class)} and
 * {@code @ConditionalOnBean(UserLookupProvider.class)}. Consuming applications that
 * require a customized {@link UserDetailsService} may provide their own {@code @Bean}
 * to replace this default.</p>
 *
 * @see UserLookupProvider
 * @see SecurityPrincipalUserDetails
 * @see SecurityPrincipal
 * @since Phase 7.2
 */
@Slf4j
public class SecurityPrincipalUserDetailsService implements UserDetailsService {

    /**
     * Sentinel password value used when the loaded {@link SecurityPrincipal} does not
     * carry an encoded password (e.g., OAuth2-only accounts). This value will never
     * match any valid BCrypt hash, ensuring that password-based authentication always
     * fails for such accounts while the lookup itself does not error.
     */
    private static final String NO_PASSWORD_SENTINEL = "";

    private final UserLookupProvider userLookupProvider;

    /**
     * Constructs the service with the required {@link UserLookupProvider} dependency.
     *
     * @param userLookupProvider the SPI implementation provided by the consuming application;
     *                           must not be {@code null}
     * @throws IllegalArgumentException if {@code userLookupProvider} is {@code null}
     */
    public SecurityPrincipalUserDetailsService(UserLookupProvider userLookupProvider) {
        Assert.notNull(userLookupProvider, "userLookupProvider must not be null");
        this.userLookupProvider = userLookupProvider;
    }

    /**
     * Loads a {@link UserDetails} instance for the given identifier by delegating to
     * {@link UserLookupProvider#findByIdentifier(String)}.
     *
     * <p>If no principal is found for the given identifier, this method throws
     * {@link UsernameNotFoundException} with a generic message that does not disclose
     * whether the identifier exists in the system. This prevents user-enumeration
     * attacks via timing or response-body analysis of the authentication endpoint.</p>
     *
     * <p>The returned {@link UserDetails} instance is a {@link SecurityPrincipalUserDetails}
     * adapter wrapping the loaded principal. The encoded password is resolved via
     * {@link #resolveEncodedPassword(SecurityPrincipal)}.</p>
     *
     * @param identifier the unique identifier submitted by the client (typically an email
     *                   or username); must not be {@code null} or blank
     * @return a non-null {@link UserDetails} instance for the found principal
     * @throws UsernameNotFoundException if no principal is found for the given identifier,
     *                                   or if the identifier is null or blank
     */
    @Override
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        if (identifier == null || identifier.isBlank()) {
            throw new UsernameNotFoundException("Authentication failed");
        }

        log.debug("Attempting to load principal for identifier: [{}]", identifier);

        SecurityPrincipal principal = userLookupProvider.findByIdentifier(identifier)
                .orElseThrow(() -> {
                    log.debug("No principal found for identifier: [{}]", identifier);
                    return new UsernameNotFoundException("Authentication failed");
                });

        String encodedPassword = resolveEncodedPassword(principal);

        log.debug("Principal loaded successfully for identifier: [{}], accountLocked: [{}]",
                identifier, principal.isAccountLocked());

        return new SecurityPrincipalUserDetails(principal, encodedPassword);
    }

    /**
     * Resolves the encoded password from the loaded {@link SecurityPrincipal}.
     *
     * <p>This method checks whether the principal implements the {@code PasswordHolder}
     * marker interface (expected from consuming applications using local password-based
     * authentication). If the principal provides an encoded password, it is returned
     * as-is for BCrypt verification by {@code DaoAuthenticationProvider}.</p>
     *
     * <p>If the principal does not implement {@code PasswordHolder} (e.g., an OAuth2-only
     * account), the {@link #NO_PASSWORD_SENTINEL} is returned. This ensures that
     * password-based authentication will fail for such accounts without requiring
     * special-case logic in the authentication provider.</p>
     *
     * <p><strong>Note:</strong> Consuming applications using local password authentication
     * must ensure their {@link SecurityPrincipal} implementation exposes the encoded
     * password via the {@code PasswordHolder} interface. If it does not, authentication
     * will always fail for password-based logins regardless of the correctness of the
     * submitted credential.</p>
     *
     * @param principal the loaded domain principal; never {@code null}
     * @return the encoded password string, or the {@link #NO_PASSWORD_SENTINEL} if
     *         the principal does not implement {@code PasswordHolder}
     */
    private String resolveEncodedPassword(SecurityPrincipal principal) {
        if (principal instanceof PasswordHolder passwordHolder) {
            return passwordHolder.getEncodedPassword();
        }
        log.debug("Principal [{}] does not implement PasswordHolder — password-based " +
                "authentication will be rejected for this account. " +
                "This is expected for OAuth2-only accounts.", principal.getIdentifier());
        return NO_PASSWORD_SENTINEL;
    }

    /**
     * Marker interface for {@link SecurityPrincipal} implementations that carry
     * a BCrypt-encoded password credential.
     *
     * <p>Consuming applications using local (username/password) authentication must
     * implement this interface on their {@link SecurityPrincipal} entity class.
     * The framework uses this interface to extract the encoded password for
     * {@code DaoAuthenticationProvider} verification without requiring the
     * {@link SecurityPrincipal} contract itself to be coupled to password storage.</p>
     *
     * <h3>Example Usage</h3>
     * <pre>{@code
     * @Entity
     * public class UserEntity implements SecurityPrincipal,
     *         SecurityPrincipalUserDetailsService.PasswordHolder {
     *
     *     @Column(nullable = false)
     *     private String passwordHash;
     *
     *     @Override
     *     public String getEncodedPassword() {
     *         return this.passwordHash;
     *     }
     * }
     * }</pre>
     *
     * <h3>OAuth2 Accounts</h3>
     * <p>For principals that authenticate exclusively via OAuth2 (Google, GitHub, etc.),
     * do NOT implement this interface. The framework detects its absence and uses a
     * sentinel password that will never match, correctly rejecting any attempt to
     * authenticate such accounts via password.</p>
     */
    public interface PasswordHolder {

        /**
         * Returns the BCrypt-encoded password hash for this principal.
         *
         * <p>This value is used exclusively by Spring Security's
         * {@code DaoAuthenticationProvider} to verify the submitted raw password.
         * It must be a BCrypt hash generated with the strength configured via
         * {@code security.core.bcrypt-strength} (default: 12).</p>
         *
         * @return the BCrypt-encoded password; must not be {@code null}
         */
        String getEncodedPassword();
    }
}
