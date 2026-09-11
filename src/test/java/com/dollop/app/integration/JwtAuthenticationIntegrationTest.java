package com.dollop.app.integration;

import com.dollop.app.autoconfigure.JwtProperties;
import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.test.TestSecurityConfig;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestSecurityConfig.class)
@TestPropertySource(properties = {
        "security.core.public-urls=/api/test/public/**",
        "security.jwt.access-secret=v9y$B&E)H@MbQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp",
        "security.jwt.refresh-secret=gVkYp3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8x/A?D(G+Kb",
        "security.jwt.cookie-name=ACCESS_TOKEN"
})
public class JwtAuthenticationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtProvider jwtProvider;

    @Test
    @DisplayName("1. Valid Access Token via Authorization Header succeeds")
    void testValidAccessTokenInHeader() throws Exception {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String token = jwtProvider.generateAccessToken(user, Collections.emptyMap());

        mockMvc.perform(get("/api/test/protected/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("authenticated"));
    }

    @Test
    @DisplayName("2. Valid Access Token via Cookie succeeds when cookie-name configured")
    void testValidAccessTokenInCookie() throws Exception {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String token = jwtProvider.generateAccessToken(user, Collections.emptyMap());

        mockMvc.perform(get("/api/test/protected/me")
                        .cookie(new Cookie("ACCESS_TOKEN", token)))
                .andExpect(status().isOk())
                .andExpect(content().string("authenticated"));
    }

    @Test
    @DisplayName("3. Invalid Signature JWT is rejected with 401 Unauthorized")
    void testInvalidSignatureJwt() throws Exception {
        String invalidToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        mockMvc.perform(get("/api/test/protected/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + invalidToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("4. Missing Authorization token is rejected with 401 Unauthorized")
    void testMissingToken() throws Exception {
        mockMvc.perform(get("/api/test/protected/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("5. Malformed Header is rejected with 401 Unauthorized")
    void testMalformedHeader() throws Exception {
        mockMvc.perform(get("/api/test/protected/me")
                        .header(HttpHeaders.AUTHORIZATION, "NotBearer xyz"))
                .andExpect(status().isUnauthorized());
    }
}
