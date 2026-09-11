package com.dollop.app.jwt;

import java.util.Map;

/**
 * Parses and verifies the integrity of JSON Web Tokens.
 *
 * <p>This interface is the central validation contract for the JWT subsystem. It supports
 * the dual-secret architecture mandated by Phase 6 Decision #2, where access tokens and
 * refresh tokens are signed with different keys. Callers must specify the appropriate
 * {@link TokenKeyType} to prevent key-confusion attacks (e.g., a refresh token being
 * accepted as a valid bearer token).</p>
 *
 * <h3>Authority Loading</h3>
 * <p>In accordance with Phase 6 Decision #1, this validator is deliberately limited to
 * verifying token integrity and extracting the principal subject. It does <em>not</em>
 * load, return, or interpret the {@code roles} / {@code authorities} claim from the token.
 * Callers must reload authorities from {@code UserLookupProvider} using the subject
 * returned by {@link #extractSubject(String)}.</p>
 *
 * <h3>Validation Scope</h3>
 * <p>Implementations must verify:</p>
 * <ul>
 *   <li>Cryptographic signature against the key identified by {@link TokenKeyType}.</li>
 *   <li>Token expiry ({@code exp} claim) — expired tokens must return {@code false} from
 *       {@link #isValid(String, TokenKeyType)}.</li>
 *   <li>Token structure — malformed JWTs must not propagate uncaught exceptions from
 *       {@link #isValid}; they must return {@code false}.</li>
 * </ul>
 * <p>Revocation checking is <em>not</em> the responsibility of this interface;
 * that concern belongs to {@link TokenRevocationStore}.</p>
 *
 * <h3>SPI Override</h3>
 * <p>The framework provides {@code DefaultJwtValidator} as the default implementation,
 * registered via {@code JwtAutoConfiguration} with
 * {@code @ConditionalOnMissingBean(JwtValidator.class)}. Consumers may replace it by
 * exposing a {@code @Bean} of this type.</p>
 *
 * @see JwtProvider
 * @see TokenKeyType
 * @see TokenRevocationStore
 * @since Phase 7.1 (contract updated)
 */
public interface JwtValidator {

    /**
     * Verifies the token's signature (using the {@link TokenKeyType#ACCESS} key) and
     * confirms it has not expired.
     *
     * <p>This method is retained for backward compatibility. New code should prefer
     * {@link #isValid(String, TokenKeyType)} to make the key context explicit and to
     * support refresh-token validation. If the token is malformed or its signature cannot
     * be verified, this method must return {@code false} rather than propagating a
     * parsing exception.</p>
     *
     * @param token the encoded JWT string; must not be {@code null}
     * @return {@code true} if the token passes signature verification and has not expired
     *         using the {@code ACCESS} key context; {@code false} otherwise
     * @deprecated Prefer {@link #isValid(String, TokenKeyType)} to make the key context
     *             explicit. This default implementation delegates to
     *             {@code isValid(token, TokenKeyType.ACCESS)}.
     */
    @Deprecated(since = "Phase 7.1", forRemoval = false)
    default boolean isValid(String token) {
        return isValid(token, TokenKeyType.ACCESS);
    }

    /**
     * Verifies the token's signature against the key identified by the given
     * {@link TokenKeyType} and confirms the token has not expired.
     *
     * <p>This is the preferred validation method. The {@code keyType} argument selects
     * which configured secret is used to verify the signature:</p>
     * <ul>
     *   <li>{@link TokenKeyType#ACCESS}  — validates using {@code security.jwt.access-secret}</li>
     *   <li>{@link TokenKeyType#REFRESH} — validates using {@code security.jwt.refresh-secret}</li>
     * </ul>
     *
     * <p>A refresh token presented with {@link TokenKeyType#ACCESS} (or vice versa) will
     * fail signature verification and return {@code false}, effectively preventing
     * cross-type token misuse.</p>
     *
     * <p>Implementations must never throw a parsing exception for malformed tokens;
     * such inputs must result in a {@code false} return value.</p>
     *
     * @param token   the encoded JWT string; must not be {@code null}
     * @param keyType the cryptographic key context to use for signature verification;
     *                must not be {@code null}
     * @return {@code true} if the token passes signature verification for the specified
     *         key type and has not expired; {@code false} otherwise
     * @throws IllegalArgumentException if {@code token} or {@code keyType} is {@code null}
     */
    boolean isValid(String token, TokenKeyType keyType);

    /**
     * Extracts all claims from a JWT without performing any caller-side validation.
     *
     * <p>This method is intended for reading custom claims (e.g., {@code tenantId},
     * {@code deviceId}) from a token that has already been validated by
     * {@link #isValid(String, TokenKeyType)}. Calling this method on an invalid or
     * expired token will result in an implementation-specific runtime exception.</p>
     *
     * <p>Callers must not use the {@code roles} or {@code authorities} claim from the
     * returned map to construct a Spring Security {@code Authentication} object.
     * Per Phase 6 Decision #1, authorities must always be loaded from
     * {@code UserLookupProvider}.</p>
     *
     * @param token the encoded JWT string that has already passed validation;
     *              must not be {@code null}
     * @return a non-null, possibly empty {@link Map} of all claims contained in the
     *         JWT payload; the map is a snapshot and modifications do not affect the token
     * @throws IllegalArgumentException if {@code token} is {@code null}
     * @throws RuntimeException         (implementation-specific) if the token is malformed,
     *                                  has an invalid signature, or has expired
     */
    Map<String, Object> extractAllClaims(String token);

    /**
     * Safely extracts the subject ({@code sub} claim) from a JWT.
     *
     * <p>The subject is the principal identifier stored at token-generation time
     * (typically an email address, username, or UUID). It is used by the JWT
     * authentication filter to look up the current principal via
     * {@code UserLookupProvider.findByIdentifier(subject)}, which in turn provides
     * the authoritative set of granted authorities (Phase 6 Decision #1).</p>
     *
     * <p>This method should only be called on a token that has already been confirmed
     * valid via {@link #isValid(String, TokenKeyType)}. Calling it on an invalid or
     * expired token produces an implementation-specific runtime exception.</p>
     *
     * <p>Unlike {@link #extractAllClaims(String)}, which returns a raw {@link Map},
     * this method provides a type-safe extraction of the single most critical claim
     * to avoid unchecked casting in the calling code.</p>
     *
     * @param token the encoded JWT string that has already passed validation;
     *              must not be {@code null}
     * @return the non-null, non-blank subject string from the {@code sub} claim
     * @throws IllegalArgumentException if {@code token} is {@code null}
     * @throws RuntimeException         (implementation-specific) if the token is malformed,
     *                                  has expired, or does not contain a {@code sub} claim
     */
    String extractSubject(String token);
}

