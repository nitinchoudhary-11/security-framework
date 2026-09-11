package com.dollop.app.integration;

import com.dollop.app.test.TestSecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestSecurityConfig.class)
@TestPropertySource(properties = {
        "security.core.public-urls=/api/test/public/**",
        "security.jwt.access-secret=v9y$B&E)H@MbQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp",
        "security.jwt.refresh-secret=gVkYp3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8x/A?D(G+Kb"
})
public class PublicUrlAndSecurityFilterIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("1. Public URL matching configured pattern succeeds without token")
    void testPublicUrlBypassesSecurity() throws Exception {
        mockMvc.perform(get("/api/test/public/ping"))
                .andExpect(status().isOk())
                .andExpect(content().string("pong"));
    }

    @Test
    @DisplayName("2. Protected URL without token fails with 401 Unauthorized")
    void testProtectedUrlRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/test/protected/me"))
                .andExpect(status().isUnauthorized());
    }
}
