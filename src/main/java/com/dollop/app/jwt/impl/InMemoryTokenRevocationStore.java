package com.dollop.app.jwt.impl;

import com.dollop.app.jwt.TokenRevocationStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link TokenRevocationStore} backed by a
 * {@link ConcurrentHashMap} and SHA-256 token ID hashing.
 *
 * <p>This implementation is suitable for development environments and single-node
 * deployments only. It stores revoked JWT IDs (JTI claims) as SHA-256 hashes in memory,
 * meaning:</p>
 * <ul>
 *   <li>Revocation state is lost on application restart.</li>
 *   <li>In a multi-node cluster, revocations applied on one node are not visible to other
 *       nodes — a revoked token may still be accepted by a different cluster member.</li>
 * </ul>
 *
 * <p>For production deployments, replace this bean by providing a {@code @Bean
 * TokenRevocationStore} backed by Redis, a relational database, or another distributed
 * store. The framework's auto-configuration uses
 * {@code @ConditionalOnMissingBean(TokenRevocationStore.class)}, so this implementation
 * is skipped automatically when a custom bean is present.</p>
 *
 * <h3>SHA-256 Hashing</h3>
 * <p>Raw JTI strings are never stored. Instead, each JTI is hashed with SHA-256 and the
 * Base64-encoded digest is used as the map key. This reduces memory usage for UUIDs and
 * prevents the revocation store from becoming a secondary source of token identifiers
 * in the event of a memory dump.</p>
 *
 * <h3>Lazy Cleanup</h3>
 * <p>{@link #isRevoked(String)} performs lazy expiry checking — if a revocation entry
 * is found but its stored expiry has passed, the entry is removed from the map on the
 * spot and {@code false} is returned. This prevents stale entries from accumulating
 * indefinitely between scheduled cleanup runs.</p>
 *
 * <h3>Scheduled Cleanup</h3>
 * <p>{@link #purgeExpired()} is annotated with {@code @Scheduled} and runs at a
 * configurable fixed-rate interval (default: 3,600,000 ms = 1 hour). The interval
 * can be overridden via the {@code security.jwt.revocation-cleanup-interval-ms} property,
 * which is set as the SpEL expression for the {@code fixedRateString} attribute.</p>
 *
 * <h3>Thread Safety</h3>
 * <p>All map operations use {@link ConcurrentHashMap}, which provides thread-safe
 * read-write access without explicit synchronisation. Lazy cleanup in {@link #isRevoked}
 * uses {@link ConcurrentHashMap#remove(Object, Object)} for atomic conditional removal.</p>
 *
 * <h3>Production Warning</h3>
 * <p>A {@code WARN} log is emitted at construction time to remind operators that this
 * implementation is not production-safe. This warning cannot be suppressed via
 * configuration — it is intentional.</p>
 *
 * @see TokenRevocationStore
 * @since Phase 7.4
 */
@Slf4j
public class InMemoryTokenRevocationStore implements TokenRevocationStore {

    /**
     * Internal map entry holding the expiry instant for a revoked token.
     *
     * @param expiry the instant at which the associated token naturally expires
     */
    private record RevocationEntry(Instant expiry) {}

    /**
     * Thread-safe map from SHA-256(tokenId) → {@link RevocationEntry}.
     */
    private final ConcurrentHashMap<String, RevocationEntry> store = new ConcurrentHashMap<>();

    /**
     * Constructs the store and emits the mandatory production-unsuitability warning.
     */
    public InMemoryTokenRevocationStore() {
        log.warn("================================================================");
        log.warn("  InMemoryTokenRevocationStore is ACTIVE.");
        log.warn("  This implementation is NOT suitable for production or");
        log.warn("  multi-node deployments. Revocation state is lost on restart");
        log.warn("  and is NOT shared across cluster nodes.");
        log.warn("  Provide a @Bean TokenRevocationStore backed by Redis or a");
        log.warn("  relational database for production use.");
        log.warn("================================================================");
    }

    /**
     * {@inheritDoc}
     *
     * <p>Stores the SHA-256 hash of the given {@code tokenId} alongside the token's
     * natural expiry. If the same {@code tokenId} has been previously revoked, the
     * stored entry is replaced (the later expiry wins — idempotent behaviour).</p>
     *
     * @param tokenId the JWT ID ({@code jti} claim) to revoke; must not be {@code null}
     *                or blank
     * @param expiry  the token's natural expiry instant; must not be {@code null}
     * @throws IllegalArgumentException if {@code tokenId} is {@code null} or blank,
     *                                  or if {@code expiry} is {@code null}
     */
    @Override
    public void revoke(String tokenId, Instant expiry) {
        Assert.hasText(tokenId, "tokenId must not be null or blank");
        Assert.notNull(expiry, "expiry must not be null");

        String hashedId = hash(tokenId);
        store.put(hashedId, new RevocationEntry(expiry));
        log.debug("Token revoked: jti=[{}] (hashed), expiry=[{}]", hashedId, expiry);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Computes the SHA-256 hash of the given {@code tokenId} and checks for its
     * presence in the revocation map. If found, the stored expiry is checked lazily:
     * if the expiry has passed, the entry is atomically removed and {@code false} is
     * returned (the token has lapsed naturally and no longer needs to be tracked).
     * If the expiry has not yet passed, {@code true} is returned.</p>
     *
     * @param tokenId the JWT ID ({@code jti} claim) to check; must not be {@code null}
     * @return {@code true} if the token was explicitly revoked and its natural expiry
     *         has not yet passed; {@code false} otherwise
     * @throws IllegalArgumentException if {@code tokenId} is {@code null}
     */
    @Override
    public boolean isRevoked(String tokenId) {
        Assert.notNull(tokenId, "tokenId must not be null");

        String hashedId = hash(tokenId);
        RevocationEntry entry = store.get(hashedId);

        if (entry == null) {
            return false;
        }

        if (Instant.now().isAfter(entry.expiry())) {
            // Lazy cleanup: entry is stale — remove atomically and report not-revoked
            store.remove(hashedId, entry);
            log.debug("Lazy cleanup: expired revocation entry removed for jti=[{}]", hashedId);
            return false;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Iterates all entries in the revocation map and removes those whose stored expiry
     * instant is before or equal to the current time. This method is annotated with
     * {@code @Scheduled} to run automatically at a configurable fixed rate (default: 1 hour).
     * It may also be called manually if the consuming application requires on-demand cleanup.</p>
     *
     * <p>The cleanup is performed using {@link ConcurrentHashMap#entrySet()} iteration,
     * which is safe for concurrent modification — entries added during iteration may or
     * may not be seen, and entries removed during iteration are excluded from future
     * iterations. This is acceptable for a cleanup task where perfect consistency is
     * not required.</p>
     */
    @Override
    @Scheduled(fixedRateString =
            "${security.jwt.revocation-cleanup-interval-ms:3600000}")
    public void purgeExpired() {
        Instant now = Instant.now();
        int[] removed = {0};

        store.entrySet().removeIf(entry -> {
            boolean expired = now.isAfter(entry.getValue().expiry());
            if (expired) {
                removed[0]++;
            }
            return expired;
        });

        if (removed[0] > 0) {
            log.debug("TokenRevocationStore scheduled cleanup: removed [{}] expired entries. " +
                    "Current store size: [{}]", removed[0], store.size());
        }
    }

    /**
     * Returns the current number of entries in the revocation store.
     *
     * <p>This method is provided for monitoring and diagnostics. The count includes
     * both active revocations and entries that are expired but have not yet been
     * cleaned up by lazy or scheduled cleanup.</p>
     *
     * @return the number of entries currently held in the store
     */
    public int size() {
        return store.size();
    }

    /**
     * Computes a SHA-256 hash of the given token ID string and returns the result
     * as a URL-safe Base64-encoded string (without padding).
     *
     * <p>The input string is encoded as UTF-8 before hashing. SHA-256 is guaranteed
     * to be available on all Java SE implementations (see
     * {@link java.security.MessageDigest} documentation), so {@link NoSuchAlgorithmException}
     * is wrapped in an {@link IllegalStateException} as it is unreachable in practice.</p>
     *
     * @param tokenId the raw JWT ID string to hash
     * @return the Base64URL-encoded SHA-256 digest of the token ID
     * @throws IllegalStateException if the SHA-256 algorithm is unexpectedly unavailable
     */
    private static String hash(String tokenId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(tokenId.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(
                    "SHA-256 algorithm is not available — this should never happen on a " +
                    "standard JVM", ex);
        }
    }
}
