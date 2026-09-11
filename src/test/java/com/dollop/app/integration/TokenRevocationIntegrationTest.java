package com.dollop.app.integration;

import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.jwt.JwtValidator;
import com.dollop.app.jwt.TokenRevocationStore;
import com.dollop.app.test.TestSecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestSecurityConfig.class)
@TestPropertySource(properties = {
        "security.core.public-urls=/api/test/public/**",
        "security.jwt.access-secret=v9y$B&E)H@MbQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp",
        "security.jwt.refresh-secret=gVkYp3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8x/A?D(G+Kb"
})
public class TokenRevocationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private JwtValidator jwtValidator;

    @Autowired
    private TokenRevocationStore tokenRevocationStore;

    @Test
    @DisplayName("1. Revoked Access Token JTI is rejected by filter with 401 Unauthorized")
    void testRevokedAccessTokenRejected() throws Exception {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String token = jwtProvider.generateAccessToken(user, Collections.emptyMap());

        Map<String, Object> claims = jwtValidator.extractAllClaims(token);
        String jti = (String) claims.get("jti");

        // Manually revoke the JTI in store
        tokenRevocationStore.revoke(jti, Instant.now().plusSeconds(3600));
        assertTrue(tokenRevocationStore.isRevoked(jti));

        // Filter must reject request with 401
        mockMvc.perform(get("/api/test/protected/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("2. Revoked JTI store cleanup removes expired entries correctly")
    void testRevocationStorePurgeExpired() {
        String expiredJti = "expired-jti-12345";
        // Revoke with past expiry
        tokenRevocationStore.revoke(expiredJti, Instant.now().minusSeconds(10));

        // Purge expired tokens
        tokenRevocationStore.purgeExpired();

        // Expired JTI must no longer be present in memory store
        assertFalse(tokenRevocationStore.isRevoked(expiredJti));
    }
}
