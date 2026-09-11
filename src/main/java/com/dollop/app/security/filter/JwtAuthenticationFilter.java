package com.dollop.app.security.filter;

import com.dollop.app.autoconfigure.JwtProperties;
import com.dollop.app.autoconfigure.SecurityCoreProperties;
import com.dollop.app.jwt.JwtValidator;
import com.dollop.app.jwt.TokenKeyType;
import com.dollop.app.jwt.TokenRevocationStore;
import com.dollop.app.security.core.SecurityErrorResponseWriter;
import com.dollop.app.security.core.exception.AccountLockedException;
import com.dollop.app.security.core.exception.TokenRevokedException;
import com.dollop.app.security.core.userdetails.SecurityPrincipalUserDetails;
import com.dollop.app.spi.user.UserLookupProvider;
import com.dollop.app.user.SecurityPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Spring Security filter that authenticates stateless HTTP requests via JWT.
 *
 * <p>This filter extends {@link OncePerRequestFilter} to guarantee exactly one execution
 * per request, regardless of how many times the filter chain is invoked (e.g., during
 * error dispatches). It intercepts every request before Spring Security's
 * {@code UsernamePasswordAuthenticationFilter}, extracts a JWT access token, validates it,
 * and populates the {@link SecurityContextHolder} with a fully authenticated
 * {@link UsernamePasswordAuthenticationToken}.</p>
 *
 * <h3>Token Extraction Priority (Phase 6 Decision #7)</h3>
 * <ol>
 *   <li><strong>Authorization: Bearer header</strong> — checked first.</li>
 *   <li><strong>HttpOnly cookie</strong> — checked second, only if
 *       {@code security.jwt.cookie-name} is configured (non-null, non-blank). If the
 *       property is absent, cookie extraction is completely disabled.</li>
 *   <li>If neither source yields a token, the request proceeds unauthenticated
 *       (anonymous) — downstream security rules handle the outcome.</li>
 * </ol>
 *
 * <h3>Public URL Bypass</h3>
 * <p>Requests matching any URL in {@code security.core.public-urls} are skipped entirely.
 * The filter does not attempt token extraction or validation for these paths, preventing
 * spurious 401 responses on endpoints like {@code /auth/login} or {@code /actuator/health}.</p>
 *
 * <h3>Double-Authentication Prevention</h3>
 * <p>If the {@link SecurityContextHolder} already contains an authenticated
 * {@link org.springframework.security.core.Authentication} at filter entry, the filter
 * exits immediately without attempting token extraction. This prevents overwriting a
 * pre-existing session-based or test-provided authentication.</p>
 *
 * <h3>Refresh Token Rejection</h3>
 * <p>A refresh token presented as a bearer access token will fail validation because
 * this filter calls {@link JwtValidator#isValid(String, TokenKeyType)} with
 * {@link TokenKeyType#ACCESS}. A refresh token is signed with a different key and will
 * not pass ACCESS validation (Phase 6 Decision #2).</p>
 *
 * <h3>Revocation Check</h3>
 * <p>After signature validation, the token's JTI claim is checked against
 * {@link TokenRevocationStore}. A revoked-but-still-valid token is rejected with a
 * {@link TokenRevokedException}, which this filter catches and translates to HTTP 401.</p>
 *
 * <h3>Authority Loading (Phase 6 Decision #1)</h3>
 * <p>Granted authorities are <em>never</em> read from the JWT claims. The principal is
 * reloaded on every request via {@link UserLookupProvider#findByIdentifier(String)},
 * and {@link SecurityPrincipal#getAuthorities()} provides the live, authoritative
 * authority set. This ensures that revoked roles take effect immediately without
 * requiring token invalidation.</p>
 *
 * <h3>Exception Handling</h3>
 * <p>All security exceptions caught within this filter are translated to JSON responses
 * via {@link SecurityErrorResponseWriter} and the filter chain is <em>not</em> continued.
 * This prevents partial authentication state from reaching downstream handlers.</p>
 *
 * @see JwtValidator
 * @see TokenRevocationStore
 * @see SecurityErrorResponseWriter
 * @see UserLookupProvider
 * @since Phase 7.4
 */
@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String JTI_CLAIM     = "jti";

    private final JwtValidator jwtValidator;
    private final UserLookupProvider userLookupProvider;
    private final TokenRevocationStore tokenRevocationStore;
    private final SecurityErrorResponseWriter errorResponseWriter;
    private final List<AntPathRequestMatcher> publicUrlMatchers;
    private final String cookieName; // null = cookie extraction disabled

    /**
     * Constructs the filter with all required dependencies.
     *
     * @param jwtValidator          validates JWT signatures and extracts claims;
     *                              must not be {@code null}
     * @param userLookupProvider    loads the live principal for authority resolution;
     *                              must not be {@code null}
     * @param tokenRevocationStore  checks whether a token has been explicitly revoked;
     *                              must not be {@code null}
     * @param errorResponseWriter   writes JSON error bodies to the servlet response;
     *                              must not be {@code null}
     * @param securityCoreProperties framework core properties (public URL list);
     *                              must not be {@code null}
     * @param jwtProperties         JWT-specific properties (cookie name);
     *                              must not be {@code null}
     * @throws IllegalArgumentException if any required parameter is {@code null}
     */
    public JwtAuthenticationFilter(
            JwtValidator jwtValidator,
            UserLookupProvider userLookupProvider,
            TokenRevocationStore tokenRevocationStore,
            SecurityErrorResponseWriter errorResponseWriter,
            SecurityCoreProperties securityCoreProperties,
            JwtProperties jwtProperties) {

        Assert.notNull(jwtValidator, "jwtValidator must not be null");
        Assert.notNull(userLookupProvider, "userLookupProvider must not be null");
        Assert.notNull(tokenRevocationStore, "tokenRevocationStore must not be null");
        Assert.notNull(errorResponseWriter, "errorResponseWriter must not be null");
        Assert.notNull(securityCoreProperties, "securityCoreProperties must not be null");
        Assert.notNull(jwtProperties, "jwtProperties must not be null");

        this.jwtValidator = jwtValidator;
        this.userLookupProvider = userLookupProvider;
        this.tokenRevocationStore = tokenRevocationStore;
        this.errorResponseWriter = errorResponseWriter;
        this.cookieName = resolveCookieName(jwtProperties);
        this.publicUrlMatchers = buildPublicUrlMatchers(securityCoreProperties.getPublicUrls());
    }

    /**
     * Core filter logic executed exactly once per request.
     *
     * <p>The full processing sequence:</p>
     * <ol>
     *   <li>Skip if request matches a configured public URL.</li>
     *   <li>Skip if the SecurityContext already contains an authenticated principal.</li>
     *   <li>Extract the token from the Authorization header or configured cookie.</li>
     *   <li>If no token found, continue the chain (anonymous request).</li>
     *   <li>Validate the token with {@link TokenKeyType#ACCESS}.</li>
     *   <li>Check the JTI against the revocation store.</li>
     *   <li>Extract the subject and load the principal from {@link UserLookupProvider}.</li>
     *   <li>Enforce account-lock state.</li>
     *   <li>Populate the {@link SecurityContextHolder} with an authenticated token.</li>
     *   <li>Continue the filter chain.</li>
     * </ol>
     *
     * @param request     the incoming HTTP request
     * @param response    the HTTP response
     * @param filterChain the remaining filter chain
     * @throws ServletException if a servlet error occurs
     * @throws IOException      if an I/O error occurs writing the response
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Step 1: Bypass public URLs entirely
        if (isPublicUrl(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Step 2: Prevent double authentication
        if (isAlreadyAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Step 3: Extract token
        String token = extractToken(request);
        if (!StringUtils.hasText(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Steps 4–9: Validate, load principal, populate SecurityContext
        try {
            processToken(token, request, response, filterChain);
        } catch (AccountLockedException ex) {
            log.debug("JWT filter: account locked — {}", ex.getMessage());
            errorResponseWriter.write(response, ex.getStatus(),
                    "Locked", ex.getMessage(), request.getRequestURI());
        } catch (TokenRevokedException ex) {
            log.debug("JWT filter: token revoked — {}", ex.getMessage());
            errorResponseWriter.write(response, 401,
                    "Unauthorized", "Authentication failed", request.getRequestURI());
        } catch (Exception ex) {
            log.debug("JWT filter: unexpected exception during token processing — {}",
                    ex.getMessage());
            errorResponseWriter.write(response, 401,
                    "Unauthorized", "Authentication failed", request.getRequestURI());
        }
    }

    /**
     * Validates the token, loads the principal, enforces account state, and populates
     * the {@link SecurityContextHolder}. On success, continues the filter chain.
     *
     * @param token       the extracted JWT access token string
     * @param request     the incoming HTTP request
     * @param response    the HTTP response
     * @param filterChain the remaining filter chain
     * @throws IOException      if writing the response fails
     * @throws ServletException if a servlet error occurs in the downstream chain
     */
    private void processToken(
            String token,
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws IOException, ServletException {

        // Step 4: Validate signature and expiry using ACCESS key
        if (!jwtValidator.isValid(token, TokenKeyType.ACCESS)) {
            log.debug("JWT filter: token failed ACCESS validation for path=[{}]",
                    request.getRequestURI());
            errorResponseWriter.write(response, 401,
                    "Unauthorized", "Authentication failed", request.getRequestURI());
            return;
        }

        // Step 5: Check revocation store using JTI claim
        Map<String, Object> claims = jwtValidator.extractAllClaims(token);
        String jti = resolveJti(claims);
        if (jti != null && tokenRevocationStore.isRevoked(jti)) {
            log.warn("JWT filter: revoked token presented: jti=[{}], path=[{}]",
                    jti, request.getRequestURI());
            throw new TokenRevokedException("Authentication failed");
        }

        // Step 6: Extract subject and reload principal (authorities NEVER from token)
        String subject = jwtValidator.extractSubject(token);
        SecurityPrincipal principal = userLookupProvider.findByIdentifier(subject)
                .orElseThrow(() -> {
                    log.debug("JWT filter: principal not found for subject=[{}]", subject);
                    return new TokenRevokedException("Authentication failed");
                });

        // Step 7: Enforce account-lock state (Phase 6 Decision #10)
        if (principal.isAccountLocked()) {
            log.debug("JWT filter: account is locked for principal=[{}]",
                    principal.getIdentifier());
            throw new AccountLockedException("Account is locked");
        }

        // Step 8: Build authenticated token and populate SecurityContextHolder
        SecurityPrincipalUserDetails userDetails =
                new SecurityPrincipalUserDetails(principal, "");

        UsernamePasswordAuthenticationToken authToken =
                UsernamePasswordAuthenticationToken.authenticated(
                        userDetails,
                        null,
                        userDetails.getAuthorities());

        authToken.setDetails(request.getRemoteAddr());

        SecurityContextHolder.getContext().setAuthentication(authToken);

        log.debug("JWT filter: principal=[{}] authenticated for path=[{}]",
                principal.getIdentifier(), request.getRequestURI());

        // Step 9: Continue filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Attempts to extract a JWT access token from the request.
     *
     * <p>Priority: Authorization Bearer header → configured HttpOnly cookie.
     * Cookie extraction is attempted only if {@code security.jwt.cookie-name} is
     * configured.</p>
     *
     * @param request the incoming HTTP request
     * @return the raw JWT string, or {@code null} if not found in any source
     */
    private String extractToken(HttpServletRequest request) {
        // Priority 1: Authorization: Bearer header
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length()).strip();
        }

        // Priority 2: HttpOnly cookie (only if cookie-name is configured)
        if (StringUtils.hasText(cookieName)) {
            return extractFromCookie(request);
        }

        return null;
    }

    /**
     * Extracts the JWT from the named HttpOnly cookie.
     *
     * @param request the incoming HTTP request
     * @return the cookie value if present, or {@code null}
     */
    private String extractFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        return Arrays.stream(cookies)
                .filter(c -> cookieName.equals(c.getName()))
                .map(Cookie::getValue)
                .filter(StringUtils::hasText)
                .findFirst()
                .orElse(null);
    }

    /**
     * Returns {@code true} if the request URI matches any of the configured public URLs.
     *
     * @param request the incoming HTTP request
     * @return {@code true} if the request is for a public endpoint
     */
    private boolean isPublicUrl(HttpServletRequest request) {
        return publicUrlMatchers.stream()
                .anyMatch(matcher -> matcher.matches(request));
    }

    /**
     * Returns {@code true} if the {@link SecurityContextHolder} already contains an
     * authenticated principal, indicating that this filter should not overwrite it.
     *
     * @return {@code true} if a non-anonymous authentication is already present
     */
    private boolean isAlreadyAuthenticated() {
        var existing = SecurityContextHolder.getContext().getAuthentication();
        return existing != null && existing.isAuthenticated()
                && !(existing instanceof org.springframework.security.authentication.AnonymousAuthenticationToken);
    }

    /**
     * Safely extracts the {@code jti} claim string from the decoded claims map.
     *
     * <p>Returns {@code null} if the claim is absent or not a non-blank {@code String}.
     * A null JTI is treated as "cannot verify revocation" — the token is still accepted
     * (revocation checking is skipped). Tokens without JTI cannot be revoked; for
     * maximum security, {@code DefaultJwtProvider} must embed a {@code jti} in all tokens.</p>
     *
     * @param claims the decoded JWT claims map
     * @return the JTI string, or {@code null} if not present or blank
     */
    private String resolveJti(Map<String, Object> claims) {
        Object jtiValue = claims.get(JTI_CLAIM);
        if (jtiValue instanceof String jti && !jti.isBlank()) {
            return jti;
        }
        return null;
    }

    /**
     * Resolves the configured cookie name from {@link JwtProperties}.
     *
     * <p>Returns {@code null} (cookie extraction disabled) if the property is not set
     * or is blank — consistent with the opt-in design (Phase 6 Decision #7).</p>
     *
     * @param jwtProperties the JWT configuration properties
     * @return the trimmed cookie name, or {@code null} if not configured
     */
    private static String resolveCookieName(JwtProperties jwtProperties) {
        String name = jwtProperties.getCookieName();
        return (StringUtils.hasText(name)) ? name.strip() : null;
    }

    /**
     * Builds an immutable list of {@link AntPathRequestMatcher} instances for the
     * configured public URLs. Uses Spring MVC-style Ant patterns.
     *
     * @param publicUrls the list of public URL patterns from configuration
     * @return an immutable list of matchers; empty if no public URLs are configured
     */
    private static List<AntPathRequestMatcher> buildPublicUrlMatchers(List<String> publicUrls) {
        if (publicUrls == null || publicUrls.isEmpty()) {
            return List.of();
        }
        return publicUrls.stream()
                .filter(StringUtils::hasText)
                .map(AntPathRequestMatcher::new)
                .toList();
    }
}
