package com.dollop.app.sample.provider;

import com.dollop.app.sample.model.SampleUserEntity;
import com.dollop.app.spi.user.UserLookupProvider;
import com.dollop.app.user.SecurityPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sample implementation of UserLookupProvider SPI storing users in memory.
 */
@Component
public class SampleUserLookupProvider implements UserLookupProvider {

    private final Map<String, SampleUserEntity> userDatabase = new ConcurrentHashMap<>();

    public SampleUserLookupProvider() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        String defaultPassword = encoder.encode("password123");

        userDatabase.put("admin@example.com", new SampleUserEntity(
                "usr_admin", "admin@example.com", defaultPassword,
                Set.of("ADMIN"), Set.of("REPORTS_EXPORT", "DOC_READ", "DOC_WRITE"), false));

        userDatabase.put("user@example.com", new SampleUserEntity(
                "usr_standard", "user@example.com", defaultPassword,
                Set.of("USER"), Set.of("DOC_READ"), false));

        userDatabase.put("locked@example.com", new SampleUserEntity(
                "usr_locked", "locked@example.com", defaultPassword,
                Set.of("USER"), Set.of(), true));
        userDatabase.put("nitin@example.com",
                new SampleUserEntity(
                        "usr_nitin",
                        "nitin@example.com",
                        defaultPassword,
                        Set.of("ADMIN"),
                        Set.of("DOC_READ", "DOC_WRITE"),
                        false));
    }

    @Override
    public Optional<SecurityPrincipal> findByIdentifier(String identifier) {
        return Optional.ofNullable(userDatabase.get(identifier));
    }

    public Optional<SecurityPrincipal> findByUsername(String username) {
        return findByIdentifier(username);
    }
}
