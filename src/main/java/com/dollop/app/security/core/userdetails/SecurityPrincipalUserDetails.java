package com.dollop.app.security.core.userdetails;

import com.dollop.app.user.SecurityPrincipal;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Adapts the framework's {@link SecurityPrincipal} contract into a Spring Security
 * {@link UserDetails} object, bridging the framework's domain model with the
 * Spring Security authentication infrastructure.
 *
 * <p>Spring Security's {@code DaoAuthenticationProvider} and {@code AuthenticationManager}
 * operate exclusively against {@link UserDetails}. This adapter class allows the framework
 * to use the consuming application's {@link SecurityPrincipal} implementation — which is
 * loaded via {@code UserLookupProvider} — without requiring the consuming application to
 * implement {@link UserDetails} directly.</p>
 *
 * <h3>Authority Mapping</h3>
 * <p>Authorities are sourced exclusively from
 * {@link SecurityPrincipal#getAuthorities()}, which reflects the live, authoritative
 * role assignments from the consuming application's persistence layer. Each authority
 * string is wrapped in a {@link SimpleGrantedAuthority}. This is consistent with
 * Phase 6 Decision #1: JWT roles claims are never used for authority resolution.</p>
 *
 * <p>If {@link SecurityPrincipal#getAuthorities()} returns {@code null} or an empty
 * set, this adapter returns an empty, unmodifiable authority collection. Spring Security
 * permits principals with no granted authorities — access control is then enforced
 * entirely by the configured security rules.</p>
 *
 * <h3>Account State Mapping</h3>
 * <p>The {@link SecurityPrincipal#isAccountLocked()} flag maps directly to
 * Spring Security's account-locked state. When {@code true}, Spring Security's
 * {@code DaoAuthenticationProvider} throws {@code LockedException} before password
 * verification, which is then handled by the framework's lock-state-aware
 * {@code AuthenticationEntryPoint} according to Phase 6 Decision #10
 * ({@code security.core.hide-account-state}).</p>
 *
 * <p>All other Spring Security account-state flags ({@code isAccountNonExpired},
 * {@code isCredentialsNonExpired}, {@code isEnabled}) return {@code true} by default.
 * Consuming applications that require these flags should either override this adapter
 * or extend {@link SecurityPrincipal} with additional state methods.</p>
 *
 * <h3>Password Handling</h3>
 * <p>The {@link #getPassword()} method returns the encoded password credential.
 * This value is provided at construction time and is used by
 * {@code DaoAuthenticationProvider} for BCrypt verification. It is never exposed
 * through the framework's public API after authentication is complete.</p>
 *
 * <h3>Thread Safety</h3>
 * <p>Instances of this class are effectively immutable once constructed. The authority
 * collection is an unmodifiable snapshot taken at construction time. This class is
 * safe for concurrent use.</p>
 *
 * @see SecurityPrincipal
 * @see SecurityPrincipalUserDetailsService
 * @since Phase 7.2
 */
public final class SecurityPrincipalUserDetails implements UserDetails {

    private static final long serialVersionUID = 1L;

    /**
     * The wrapped domain principal. Exposed via {@link #getPrincipal()} to allow
     * downstream components (e.g., the JWT filter, audit listeners) to access the
     * full {@link SecurityPrincipal} contract after authentication is complete.
     */
    @Getter
    private final SecurityPrincipal principal;

    /**
     * The encoded password credential used by {@code DaoAuthenticationProvider}
     * for BCrypt verification. Stored transiently within the authentication lifecycle
     * and not propagated further.
     */
    private final String encodedPassword;

    /**
     * An unmodifiable snapshot of the granted authorities, built from
     * {@link SecurityPrincipal#getAuthorities()} at construction time.
     */
    private final Collection<GrantedAuthority> authorities;

    /**
     * Constructs a {@code SecurityPrincipalUserDetails} adapter for the given principal.
     *
     * <p>The authority collection is computed eagerly at construction time from the
     * principal's current authority set. Any subsequent changes to the principal's
     * role assignments are not reflected in this instance — the instance is a snapshot
     * valid for the duration of the authentication request lifecycle.</p>
     *
     * @param principal       the domain principal loaded by {@code UserLookupProvider};
     *                        must not be {@code null}
     * @param encodedPassword the BCrypt-encoded password for the principal, used by
     *                        {@code DaoAuthenticationProvider} for credential verification;
     *                        must not be {@code null}
     * @throws IllegalArgumentException if {@code principal} or {@code encodedPassword}
     *                                  is {@code null}
     */
    public SecurityPrincipalUserDetails(SecurityPrincipal principal, String encodedPassword) {
        Assert.notNull(principal, "principal must not be null");
        Assert.notNull(encodedPassword, "encodedPassword must not be null");

        this.principal = principal;
        this.encodedPassword = encodedPassword;
        this.authorities = buildAuthorities(principal.getAuthorities());
    }

    /**
     * Returns the collection of granted authorities derived from
     * {@link SecurityPrincipal#getAuthorities()}.
     *
     * <p>Each authority string is wrapped in a {@link SimpleGrantedAuthority}.
     * The returned collection is unmodifiable and is a snapshot taken at construction
     * time. Returns an empty collection (never {@code null}) if the principal has
     * no assigned roles.</p>
     *
     * @return an unmodifiable, non-null collection of granted authorities
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * Returns the BCrypt-encoded password used by {@code DaoAuthenticationProvider}
     * to verify the presented credentials.
     *
     * @return the encoded password; never {@code null}
     */
    @Override
    public String getPassword() {
        return encodedPassword;
    }

    /**
     * Returns the principal's unique identifier, used by Spring Security as the
     * username for {@link UserDetails} lookup and {@code Authentication} population.
     *
     * <p>This value corresponds to {@link SecurityPrincipal#getIdentifier()} —
     * typically an email address, username, or UUID.</p>
     *
     * @return the principal identifier; never {@code null}
     */
    @Override
    public String getUsername() {
        return principal.getIdentifier();
    }

    /**
     * Returns {@code true} always. Account expiry is not modelled in
     * {@link SecurityPrincipal}. Consuming applications that require account-expiry
     * semantics should extend the principal contract and override this adapter.
     *
     * @return {@code true}
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Returns {@code true} if the account is <em>not</em> locked, {@code false} if it is.
     *
     * <p>This maps directly to the inverse of {@link SecurityPrincipal#isAccountLocked()}.
     * When this method returns {@code false}, Spring Security's
     * {@code DaoAuthenticationProvider} throws a {@code LockedException}, which is
     * then translated to HTTP 423 (or HTTP 401 if {@code security.core.hide-account-state=true})
     * by the framework's lock-state-aware {@code AuthenticationEntryPoint}.</p>
     *
     * @return {@code false} if the account is locked; {@code true} otherwise
     */
    @Override
    public boolean isAccountNonLocked() {
        return !principal.isAccountLocked();
    }

    /**
     * Returns {@code true} always. Credential expiry is not modelled in
     * {@link SecurityPrincipal}. Consuming applications that require credential-expiry
     * semantics (e.g., forced password change) should extend the principal contract
     * and override this adapter.
     *
     * @return {@code true}
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Returns {@code true} always. Account enablement is not separately modelled in
     * {@link SecurityPrincipal}; the combination of {@link #isAccountNonLocked()} and
     * the framework's authentication flow is sufficient for the default security model.
     * Consuming applications requiring explicit enable/disable semantics should extend
     * the principal contract.
     *
     * @return {@code true}
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

    /**
     * Builds an unmodifiable authority collection from the given set of authority strings.
     *
     * <p>Null or empty sets are handled gracefully by returning an empty collection.
     * Null individual entries within the set are filtered out to prevent
     * {@link NullPointerException} inside Spring Security's authorization logic.</p>
     *
     * @param authorityStrings the raw authority strings from {@link SecurityPrincipal#getAuthorities()}
     * @return an unmodifiable, non-null collection of {@link GrantedAuthority} instances
     */
    private static Collection<GrantedAuthority> buildAuthorities(Set<String> authorityStrings) {
        if (authorityStrings == null || authorityStrings.isEmpty()) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableSet(
                authorityStrings.stream()
                        .filter(authority -> authority != null && !authority.isBlank())
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toSet())
        );
    }
}
