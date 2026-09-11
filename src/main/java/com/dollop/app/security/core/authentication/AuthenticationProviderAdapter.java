package com.dollop.app.security.core.authentication;

import com.dollop.app.auth.AuthenticationStrategy;
import com.dollop.app.auth.model.AuthenticationRequest;
import com.dollop.app.security.core.userdetails.SecurityPrincipalUserDetails;
import com.dollop.app.user.SecurityPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import java.util.List;

/**
 * Spring Security {@link AuthenticationProvider} that adapts the framework's
 * {@link AuthenticationStrategy} SPI pipeline into the Spring Security authentication
 * contract.
 *
 * <p>This class replaces the default {@code DaoAuthenticationProvider} as the primary
 * authentication mechanism when one or more {@link AuthenticationStrategy} beans are
 * present. It performs the following functions:</p>
 * <ol>
 *   <li>Accepts a {@link UsernamePasswordAuthenticationToken} from
 *       {@code AuthenticationManager}.</li>
 *   <li>Delegates to the registered {@link AuthenticationStrategy} pipeline to locate
 *       a strategy that supports the incoming credential type.</li>
 *   <li>If no custom strategy supports the credential, falls back to the standard
 *       Spring Security {@link UserDetailsService} + {@link PasswordEncoder} flow,
 *       preserving compatibility with default password-based authentication.</li>
 *   <li>Enforces account-lock checking per Phase 6 Decision #10.</li>
 *   <li>Returns a fully populated {@link UsernamePasswordAuthenticationToken} with
 *       the {@link SecurityPrincipalUserDetails} as the principal on success.</li>
 * </ol>
 *
 * <h3>Strategy Pipeline</h3>
 * <p>The provider iterates the list of registered {@link AuthenticationStrategy} beans
 * in the order they are returned by the Spring context (typically declaration order).
 * The first strategy whose {@link AuthenticationStrategy#supports(Class)} returns
 * {@code true} for the credential type is selected. If no strategy matches, the
 * standard password-based flow is used as the fallback.</p>
 *
 * <p>This design allows consuming applications to register custom strategies (e.g.,
 * for API key authentication, magic link, or biometric) without replacing the entire
 * authentication infrastructure.</p>
 *
 * <h3>Authority Source</h3>
 * <p>In all cases, granted authorities are derived from
 * {@link SecurityPrincipal#getAuthorities()} — never from any token claim or credential
 * field. This is consistent with Phase 6 Decision #1.</p>
 *
 * <h3>Fallback Behaviour</h3>
 * <p>When the standard password-based fallback is used, this provider loads the
 * {@link UserDetails} via {@link UserDetailsService}, verifies the submitted password
 * with {@link PasswordEncoder}, and checks account state before returning the
 * authenticated token. This behaviour is functionally equivalent to
 * {@code DaoAuthenticationProvider} but routes through the framework's adapter chain.</p>
 *
 * <h3>Bean Registration</h3>
 * <p>This class is registered in {@code SecurityCoreAutoConfiguration} and injected into
 * the {@code ProviderManager} (Spring Security's {@code AuthenticationManager}). It is
 * registered only when at least one {@link AuthenticationStrategy} bean is present in
 * the context; otherwise, the standard {@code DaoAuthenticationProvider} is used by
 * Spring Security's auto-configuration.</p>
 *
 * <h3>Thread Safety</h3>
 * <p>This class is stateless after construction. All state is held in the immutable
 * strategy list and the injected dependencies. Concurrent authentication requests are
 * safe.</p>
 *
 * @see AuthenticationStrategy
 * @see SecurityPrincipalUserDetails
 * @see SecurityPrincipalUserDetailsService
 * @since Phase 7.2
 */
@Slf4j
public class AuthenticationProviderAdapter implements AuthenticationProvider {

    private final List<AuthenticationStrategy<?>> strategies;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    /**
     * Constructs the provider with the required dependencies.
     *
     * <p>The {@code strategies} list may be empty, in which case this provider always
     * falls back to the standard password-based flow. The list is expected to be
     * provided by Spring's auto-wired list injection, which collects all
     * {@link AuthenticationStrategy} beans in declaration order.</p>
     *
     * @param strategies          the ordered list of custom authentication strategies;
     *                            must not be {@code null}, but may be empty
     * @param userDetailsService  the {@link UserDetailsService} used for the standard
     *                            password-based fallback; must not be {@code null}
     * @param passwordEncoder     the {@link PasswordEncoder} used to verify submitted
     *                            passwords against stored BCrypt hashes; must not be
     *                            {@code null}
     * @throws IllegalArgumentException if any parameter is {@code null}
     */
    public AuthenticationProviderAdapter(
            List<AuthenticationStrategy<?>> strategies,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {

        Assert.notNull(strategies, "strategies list must not be null");
        Assert.notNull(userDetailsService, "userDetailsService must not be null");
        Assert.notNull(passwordEncoder, "passwordEncoder must not be null");

        this.strategies = List.copyOf(strategies);
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Performs authentication for a {@link UsernamePasswordAuthenticationToken}.
     *
     * <p>The authentication flow is as follows:</p>
     * <ol>
     *   <li>Extract the identifier (principal name) and raw credential from the token.</li>
     *   <li>Attempt to find a matching {@link AuthenticationStrategy} via the pipeline.</li>
     *   <li>If a matching strategy is found, delegate authentication to it.</li>
     *   <li>If no strategy matches, fall back to standard password-based authentication.</li>
     *   <li>Enforce account-lock state on the resulting principal.</li>
     *   <li>Return a fully authenticated {@link UsernamePasswordAuthenticationToken}.</li>
     * </ol>
     *
     * @param authentication the unauthenticated token produced by Spring Security from
     *                       the login request; must not be {@code null}
     * @return a fully authenticated {@link UsernamePasswordAuthenticationToken} with
     *         the principal set to the {@link SecurityPrincipalUserDetails} adapter
     *         and authorities populated from {@link SecurityPrincipal#getAuthorities()}
     * @throws BadCredentialsException if the submitted credentials do not match
     * @throws LockedException         if the account is locked per
     *                                 {@link SecurityPrincipal#isAccountLocked()}
     * @throws AuthenticationException for any other authentication failure
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String identifier = resolveIdentifier(authentication);
        Object rawCredential = authentication.getCredentials();

        log.debug("Authentication attempt for identifier: [{}]", identifier);

        AuthenticationStrategy<?> matchedStrategy = findSupportingStrategy(rawCredential);

        if (matchedStrategy != null) {
            return authenticateViaStrategy(matchedStrategy, identifier, rawCredential);
        }

        return authenticateViaPasswordFallback(identifier, rawCredential);
    }

    /**
     * Returns {@code true} if this provider supports
     * {@link UsernamePasswordAuthenticationToken}.
     *
     * <p>This provider is exclusively designed to handle the standard username-and-password
     * token type. It does not support OAuth2 or pre-authenticated token types.</p>
     *
     * @param authenticationClass the class of the authentication token to check
     * @return {@code true} if {@code authenticationClass} is
     *         {@link UsernamePasswordAuthenticationToken} or a subtype thereof
     */
    @Override
    public boolean supports(Class<?> authenticationClass) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authenticationClass);
    }

    /**
     * Searches the strategy pipeline for the first strategy that supports the given
     * credential type.
     *
     * <p>The credential class is extracted from the raw credential object. If the
     * credential is {@code null}, no strategy will match and the method returns
     * {@code null}, causing the fallback flow to be used.</p>
     *
     * @param rawCredential the raw credential object extracted from the authentication token
     * @return the first matching {@link AuthenticationStrategy}, or {@code null} if none match
     */
    @SuppressWarnings("rawtypes")
    private AuthenticationStrategy findSupportingStrategy(Object rawCredential) {
        if (rawCredential == null) {
            return null;
        }
        Class<?> credentialClass = rawCredential.getClass();
        return strategies.stream()
                .filter(strategy -> strategy.supports(credentialClass))
                .findFirst()
                .orElse(null);
    }

    /**
     * Delegates authentication to the matched {@link AuthenticationStrategy}.
     *
     * <p>The strategy receives the raw credential and returns a fully populated
     * {@link SecurityPrincipal}. Account-lock state is then enforced before building
     * the successful authentication token.</p>
     *
     * <p>Any unchecked exception thrown by the strategy is caught and rethrown as a
     * {@link BadCredentialsException} if it is not already a Spring Security
     * {@link AuthenticationException}, preventing internal exception details from leaking
     * to the authentication response.</p>
     *
     * @param strategy      the selected authentication strategy
     * @param identifier    the user's identifier (for logging)
     * @param rawCredential the raw credential to pass to the strategy
     * @return a fully authenticated {@link UsernamePasswordAuthenticationToken}
     * @throws AuthenticationException if authentication fails
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private Authentication authenticateViaStrategy(
            AuthenticationStrategy strategy,
            String identifier,
            Object rawCredential) throws AuthenticationException {

        log.debug("Delegating authentication to strategy [{}] for identifier: [{}]",
                strategy.getClass().getSimpleName(), identifier);

        SecurityPrincipal principal;
        try {
            principal = strategy.authenticate(rawCredential);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.debug("AuthenticationStrategy [{}] threw an exception for identifier [{}]: {}",
                    strategy.getClass().getSimpleName(), identifier, ex.getMessage());
            throw new BadCredentialsException("Authentication failed", ex);
        }

        enforceAccountNotLocked(principal);

        log.debug("Authentication via strategy [{}] successful for identifier: [{}]",
                strategy.getClass().getSimpleName(), identifier);

        SecurityPrincipalUserDetails userDetails = toUserDetails(principal);
        return UsernamePasswordAuthenticationToken.authenticated(
                userDetails, null, userDetails.getAuthorities());
    }

    /**
     * Performs standard password-based authentication via {@link UserDetailsService}
     * and {@link PasswordEncoder}.
     *
     * <p>This fallback path replicates the core behaviour of Spring Security's
     * {@code DaoAuthenticationProvider}:</p>
     * <ol>
     *   <li>Load {@link UserDetails} via {@link UserDetailsService#loadUserByUsername(String)}.</li>
     *   <li>Assert the loaded principal's account is not locked.</li>
     *   <li>Verify the submitted password against the stored BCrypt hash.</li>
     *   <li>Return an authenticated token on success.</li>
     * </ol>
     *
     * <p>Password mismatch always results in a {@link BadCredentialsException} with a
     * generic message, preventing user-enumeration via differing error messages for
     * "user not found" vs "wrong password".</p>
     *
     * @param identifier    the user's identifier submitted in the login request
     * @param rawCredential the raw credential (expected to be a {@code String} password)
     * @return a fully authenticated {@link UsernamePasswordAuthenticationToken}
     * @throws BadCredentialsException if the password is incorrect or the credential
     *                                 is not a {@code String}
     * @throws LockedException         if the account is locked
     */
    private Authentication authenticateViaPasswordFallback(
            String identifier,
            Object rawCredential) throws AuthenticationException {

        log.debug("No matching AuthenticationStrategy found — using password fallback " +
                "for identifier: [{}]", identifier);

        UserDetails userDetails = userDetailsService.loadUserByUsername(identifier);

        if (!(userDetails instanceof SecurityPrincipalUserDetails spud)) {
            throw new BadCredentialsException("Authentication failed");
        }

        enforceAccountNotLocked(spud.getPrincipal());

        if (!(rawCredential instanceof String rawPassword)) {
            throw new BadCredentialsException("Authentication failed");
        }

        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            log.debug("Password verification failed for identifier: [{}]", identifier);
            throw new BadCredentialsException("Authentication failed");
        }

        log.debug("Password-based authentication successful for identifier: [{}]", identifier);

        return UsernamePasswordAuthenticationToken.authenticated(
                userDetails, null, userDetails.getAuthorities());
    }

    /**
     * Enforces the account-lock constraint defined in {@link SecurityPrincipal#isAccountLocked()}.
     *
     * <p>If the principal's account is locked, a {@link LockedException} is thrown.
     * Spring Security's {@code ExceptionTranslationFilter} catches this and delegates to
     * the configured {@code AuthenticationEntryPoint}, which returns HTTP 423 or HTTP 401
     * depending on the {@code security.core.hide-account-state} property (Phase 6 Decision #10).</p>
     *
     * @param principal the principal whose lock state is to be checked
     * @throws LockedException if the principal's account is locked
     */
    private void enforceAccountNotLocked(SecurityPrincipal principal) {
        if (principal.isAccountLocked()) {
            log.debug("Authentication rejected — account is locked for identifier: [{}]",
                    principal.getIdentifier());
            throw new LockedException("Account is locked");
        }
    }

    /**
     * Wraps a {@link SecurityPrincipal} in a {@link SecurityPrincipalUserDetails} adapter.
     *
     * <p>The encoded password is not required here because this adapter is constructed
     * after a strategy-based authentication has already completed — no further password
     * verification is performed at this point. A sentinel empty string is used as the
     * password value.</p>
     *
     * @param principal the authenticated domain principal
     * @return a {@link SecurityPrincipalUserDetails} adapter for the principal
     */
    private SecurityPrincipalUserDetails toUserDetails(SecurityPrincipal principal) {
        return new SecurityPrincipalUserDetails(principal, "");
    }

    /**
     * Extracts the principal identifier string from the authentication token.
     *
     * <p>Spring Security places the submitted identifier (username or email) in
     * {@link Authentication#getPrincipal()} as a {@code String} for
     * {@link UsernamePasswordAuthenticationToken}. This method performs a safe
     * extraction and throws {@link BadCredentialsException} if the value is missing.</p>
     *
     * @param authentication the incoming authentication token
     * @return the identifier string; never {@code null} or blank
     * @throws BadCredentialsException if the principal is null or not a {@code String}
     */
    private String resolveIdentifier(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof String identifier) || identifier.isBlank()) {
            throw new BadCredentialsException("Authentication failed");
        }
        return identifier;
    }

    /**
     * Builds an {@link AuthenticationRequest} from the submitted credentials for use
     * with {@link AuthenticationStrategy} pipeline components that expect a typed request
     * model rather than raw credential objects.
     *
     * <p>This method is provided as a utility for strategies that accept
     * {@link AuthenticationRequest} as their credential type. The {@code clientIp}
     * and {@code additionalMetadata} fields are not populated here — strategies requiring
     * these fields should receive them through a richer credential type or via a
     * request-scoped context holder.</p>
     *
     * @param identifier    the user's identifier
     * @param rawCredential the raw credential string (password, token, etc.)
     * @return a minimal {@link AuthenticationRequest} containing the identifier and credential
     */
    public static AuthenticationRequest buildAuthenticationRequest(
            String identifier, String rawCredential) {
        return AuthenticationRequest.builder()
                .identifier(identifier)
                .credentials(rawCredential)
                .build();
    }
}
