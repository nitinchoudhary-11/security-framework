package com.dollop.app.integration;

import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.test.TestSecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.Set;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestSecurityConfig.class)
@TestPropertySource(properties = {
        "security.core.public-urls=/api/test/public/**",
        "security.jwt.access-secret=v9y$B&E)H@MbQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp",
        "security.jwt.refresh-secret=gVkYp3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8x/A?D(G+Kb"
})
public class SecurityExceptionHandlingIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtProvider jwtProvider;

    @Test
    @DisplayName("1. Unauthenticated request returns structured 401 SecurityErrorResponse")
    void testUnauthenticatedReturns401Json() throws Exception {
        mockMvc.perform(get("/api/test/protected/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")))
                .andExpect(jsonPath("$.timestamp", notNullValue()))
                .andExpect(jsonPath("$.path", is("/api/test/protected/me")));
    }

    @Test
    @DisplayName("2. Access Denied returns structured 403 SecurityErrorResponse")
    void testAccessDeniedReturns403Json() throws Exception {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String token = jwtProvider.generateAccessToken(user, Collections.emptyMap());

        mockMvc.perform(get("/api/test/admin-only")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status", is(403)))
                .andExpect(jsonPath("$.error", is("Forbidden")))
                .andExpect(jsonPath("$.timestamp", notNullValue()));
    }

    @Test
    @DisplayName("3. Locked account presented via JWT returns 423 Locked SecurityErrorResponse")
    void testLockedAccountReturns423Json() throws Exception {
        var lockedUser = new TestSecurityConfig.TestUser("locked_user", Set.of("USER"), Set.of(), true);
        String token = jwtProvider.generateAccessToken(lockedUser, Collections.emptyMap());

        mockMvc.perform(get("/api/test/protected/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().is(423))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status", is(423)))
                .andExpect(jsonPath("$.error", is("Locked")))
                .andExpect(jsonPath("$.message", is("Account is locked")));
    }
}
