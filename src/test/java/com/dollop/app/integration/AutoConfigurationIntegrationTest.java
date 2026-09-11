package com.dollop.app.integration;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.TestPropertySource;

import com.dollop.app.autoconfigure.SecurityCoreAutoConfiguration;
import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.jwt.JwtValidator;
import com.dollop.app.jwt.RefreshTokenService;
import com.dollop.app.jwt.TokenRevocationStore;
import com.dollop.app.jwt.impl.InMemoryTokenRevocationStore;
import com.dollop.app.test.TestSecurityConfig;


@SpringBootTest
@Import(TestSecurityConfig.class)
@TestPropertySource(properties = {
        "security.core.enabled=true",
        "security.jwt.access-secret=v9y$B&E)H@MbQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp",
        "security.jwt.refresh-secret=gVkYp3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8x/A?D(G+Kb"
})
public class AutoConfigurationIntegrationTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    @DisplayName("1. SecurityCoreAutoConfiguration registers core security beans automatically")
    void testSecurityCoreAutoConfigurationBeansPresent() {
        assertNotNull(applicationContext.getBean(SecurityCoreAutoConfiguration.class));
        assertNotNull(applicationContext.getBean(PasswordEncoder.class));
        assertNotNull(applicationContext.getBean(SecurityFilterChain.class));
    }

    @Test
    @DisplayName("2. JwtAutoConfiguration registers JWT subsystem beans when access-secret configured")
    void testJwtAutoConfigurationBeansPresent() {
        assertNotNull(applicationContext.getBean(JwtValidator.class));
        assertNotNull(applicationContext.getBean(JwtProvider.class));
        assertNotNull(applicationContext.getBean(RefreshTokenService.class));
        assertNotNull(applicationContext.getBean(TokenRevocationStore.class));
    }

    @Test
    @DisplayName("3. Default TokenRevocationStore is InMemoryTokenRevocationStore fallback")
    void testDefaultTokenRevocationStoreFallback() {
        TokenRevocationStore store = applicationContext.getBean(TokenRevocationStore.class);
        assertInstanceOf(InMemoryTokenRevocationStore.class, store);
    }
}
