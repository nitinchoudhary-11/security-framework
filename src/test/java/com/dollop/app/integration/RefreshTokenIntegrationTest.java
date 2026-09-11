package com.dollop.app.integration;

import com.dollop.app.auth.model.AuthenticationResult;
import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.jwt.JwtValidator;
import com.dollop.app.jwt.RefreshTokenService;
import com.dollop.app.jwt.TokenKeyType;
import com.dollop.app.jwt.TokenRevocationStore;
import com.dollop.app.security.core.exception.TokenRevokedException;
import com.dollop.app.test.TestSecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Import(TestSecurityConfig.class)
@TestPropertySource(properties = {
        "security.jwt.access-secret=v9y$B&E)H@MbQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp",
        "security.jwt.refresh-secret=gVkYp3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8x/A?D(G+Kb"
})
public class RefreshTokenIntegrationTest {

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private JwtValidator jwtValidator;

    @Autowired
    private TokenRevocationStore tokenRevocationStore;

    @Test
    @DisplayName("1. Successful Refresh Token Rotation (RTR) produces new token pair")
    void testSuccessfulRefreshTokenRotation() {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String initialRefreshToken = jwtProvider.generateRefreshToken(user);

        AuthenticationResult result = refreshTokenService.refresh(initialRefreshToken);

        assertNotNull(result);
        assertNotNull(result.getAccessToken());
        assertNotNull(result.getRefreshToken());
        assertNotEquals(initialRefreshToken, result.getRefreshToken());

        assertTrue(jwtValidator.isValid(result.getAccessToken(), TokenKeyType.ACCESS));
        assertTrue(jwtValidator.isValid(result.getRefreshToken(), TokenKeyType.REFRESH));
    }

    @Test
    @DisplayName("2. Replay attack with previously consumed refresh token is rejected")
    void testReplayAttackPrevention() {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String initialRefreshToken = jwtProvider.generateRefreshToken(user);

        // First usage succeeds and rotates token
        AuthenticationResult firstRefresh = refreshTokenService.refresh(initialRefreshToken);
        assertNotNull(firstRefresh);

        // Second usage (replay) must throw TokenRevokedException
        assertThrows(TokenRevokedException.class, () -> refreshTokenService.refresh(initialRefreshToken));
    }

    @Test
    @DisplayName("3. Explicitly revoked refresh token cannot be refreshed")
    void testExplicitRevocation() {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String refreshToken = jwtProvider.generateRefreshToken(user);

        refreshTokenService.revoke(refreshToken);

        assertThrows(TokenRevokedException.class, () -> refreshTokenService.refresh(refreshToken));
    }

    @Test
    @DisplayName("4. Presenting refresh token as access token is rejected by key type verification")
    void testRefreshTokenUsedAsAccessToken() {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String refreshToken = jwtProvider.generateRefreshToken(user);

        // ACCESS key validation must return false for a token signed with REFRESH key
        assertFalse(jwtValidator.isValid(refreshToken, TokenKeyType.ACCESS));
    }
}
