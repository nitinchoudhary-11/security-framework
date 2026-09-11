package com.dollop.app.jwt.model;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * An immutable value object representing the verified payload of a parsed JSON Web Token.
 *
 * <p>{@code JwtClaims} is the typed result of a successful JWT parse operation. It captures
 * the standard registered claims ({@code sub}, {@code iat}, {@code exp}) and any custom
 * claims injected at token-generation time. It is returned by the JWT authentication
 * filter after calling {@link com.dollop.app.jwt.JwtValidator} and is passed downstream
 * for principal resolution.</p>
 *
 * <h3>Authority Loading — Phase 6 Decision #1</h3>
 * <p><strong>The {@link #rolesReferenceOnly} field must NEVER be used to construct a
 * Spring Security {@code Authentication} object or to make access-control decisions.</strong>
 * The roles embedded in a JWT are considered reference-only metadata and are never trusted
 * for authorization. The authoritative source of granted authorities is always
 * {@code UserLookupProvider.findByIdentifier(subject)}, which loads the current, live
 * role assignments from the consuming application's persistence layer.</p>
 *
 * <p>The roles field exists solely to facilitate logging, debugging, and audit trail
 * enrichment — scenarios where the token's embedded claim provides useful context without
 * being used as an authorization decision input.</p>
 *
 * <h3>Immutability</h3>
 * <p>This class is annotated with Lombok {@code @Value} and {@code @Builder}, making all
 * fields {@code final} and providing a type-safe builder. The {@code customClaims} map
 * should be wrapped in {@link Collections#unmodifiableMap(Map)} by the builder caller
 * to preserve immutability guarantees at the collection level.</p>
 *
 * @see com.dollop.app.jwt.JwtValidator
 * @see com.dollop.app.jwt.JwtProvider
 * @since Phase 7.1 (field renamed for Decision #1 enforcement)
 */
@Value
@Builder
public class JwtClaims {

    /**
     * The principal identifier stored in the {@code sub} (subject) claim.
     *
     * <p>This value is used to look up the authenticated principal via
     * {@code UserLookupProvider.findByIdentifier(subject)} after the token is validated.
     * It typically contains an email address, username, or UUID — whatever the consuming
     * application used as the unique user identifier at login time.</p>
     */
    String subject;

    /**
     * The role strings parsed from the JWT payload — <strong>FOR REFERENCE ONLY</strong>.
     *
     * <p><strong>⚠ DO NOT USE FOR AUTHORIZATION — Phase 6 Decision #1 ⚠</strong></p>
     * <p>These roles were embedded in the token at the time of issuance. They represent
     * a point-in-time snapshot that may be stale. Role assignments can change between
     * token issuance and the current request (e.g., due to privilege revocation or
     * role reassignment). Using this field to make access-control decisions would allow
     * a user to retain elevated privileges after their roles have been revoked.</p>
     *
     * <p><strong>Correct authority loading pattern:</strong></p>
     * <pre>{@code
     * // CORRECT — always reload from persistence
     * SecurityPrincipal principal = userLookupProvider
     *     .findByIdentifier(jwtClaims.getSubject())
     *     .orElseThrow(...);
     * Set<String> authorities = principal.getAuthorities();
     *
     * // WRONG — never use this field for authorization
     * Set<String> authorities = jwtClaims.getRolesReferenceOnly(); // DO NOT DO THIS
     * }</pre>
     *
     * <p>Legitimate uses of this field include:</p>
     * <ul>
     *   <li>Audit log enrichment (recording what roles the token claimed at issuance)</li>
     *   <li>Debug output and observability tracing</li>
     *   <li>Detecting role drift between token-time and request-time (monitoring)</li>
     * </ul>
     */
    Set<String> rolesReferenceOnly;

    /**
     * The instant at which the token was issued, corresponding to the {@code iat} claim.
     *
     * <p>Can be used to calculate the age of the token or to detect tokens that were
     * issued before a security event (e.g., a password change) and should be treated
     * as suspect.</p>
     */
    Instant issuedAt;

    /**
     * The instant at which the token expires, corresponding to the {@code exp} claim.
     *
     * <p>This value is validated by {@link com.dollop.app.jwt.JwtValidator} during signature
     * verification. It is exposed here for audit and logging purposes. Callers must not
     * re-validate expiry from this field — they must rely on the validator to reject
     * expired tokens before this object is ever constructed.</p>
     */
    Instant expiresAt;

    /**
     * Additional custom claims injected into the token payload at generation time.
     *
     * <p>This map captures application-specific claims that do not correspond to any
     * standard JWT registered claim (e.g., {@code tenantId}, {@code deviceId},
     * {@code sessionTag}). The keys and values are determined by the caller of
     * {@link com.dollop.app.jwt.JwtProvider#generateAccessToken(
     * com.dollop.app.user.SecurityPrincipal, Map)} at login time.</p>
     *
     * <p>The map is a snapshot of the token payload. Modifications to the returned map
     * do not affect the token or any cached state. For guaranteed immutability, builders
     * should wrap the provided map with {@link Collections#unmodifiableMap(Map)} before
     * passing it to this field.</p>
     */
    Map<String, Object> customClaims;
}

