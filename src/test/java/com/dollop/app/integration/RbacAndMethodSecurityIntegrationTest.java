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
        "security.rbac.enabled=true"
})
public class RbacAndMethodSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtProvider jwtProvider;

    @Test
    @DisplayName("1. User with ROLE_ADMIN accesses @PreAuthorize('hasRole(\"ADMIN\")') successfully")
    void testAdminAccessesAdminEndpoint() throws Exception {
        var admin = new TestSecurityConfig.TestUser("admin", Set.of("ADMIN"), Set.of(), false);
        String token = jwtProvider.generateAccessToken(admin, Collections.emptyMap());

        mockMvc.perform(get("/api/test/admin-only")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("admin-content"));
    }

    @Test
    @DisplayName("2. Role Hierarchy: ROLE_ADMIN implies ROLE_USER and accesses user-only endpoint")
    void testAdminHierarchyExpandsToUser() throws Exception {
        var admin = new TestSecurityConfig.TestUser("admin", Set.of("ADMIN"), Set.of(), false);
        String token = jwtProvider.generateAccessToken(admin, Collections.emptyMap());

        mockMvc.perform(get("/api/test/user-only")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("user-content"));
    }

    @Test
    @DisplayName("3. Regular USER without ADMIN role is denied access to admin endpoint with 403 Forbidden")
    void testUserDeniedAdminEndpoint() throws Exception {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of(), false);
        String token = jwtProvider.generateAccessToken(user, Collections.emptyMap());

        mockMvc.perform(get("/api/test/admin-only")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("4. @PreAuthorize('hasAuthority(\"WRITE_DOCS\")') succeeds for principal holding authority")
    void testAuthorityCheckGranted() throws Exception {
        var admin = new TestSecurityConfig.TestUser("admin", Set.of("ADMIN"), Set.of("WRITE_DOCS"), false);
        String token = jwtProvider.generateAccessToken(admin, Collections.emptyMap());

        mockMvc.perform(get("/api/test/authority-check")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("authority-granted"));
    }

    @Test
    @DisplayName("5. @PreAuthorize('hasPermission(\"document\", \"read\")') grants access when permission evaluator allows")
    void testPermissionEvaluatorReadGranted() throws Exception {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of("READ_DOCS"), false);
        String token = jwtProvider.generateAccessToken(user, Collections.emptyMap());

        mockMvc.perform(get("/api/test/permission-read")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("permission-read-granted"));
    }

    @Test
    @DisplayName("6. @PreAuthorize('hasPermission(\"document\", \"write\")') denies access when permission is missing")
    void testPermissionEvaluatorWriteDenied() throws Exception {
        var user = new TestSecurityConfig.TestUser("john", Set.of("USER"), Set.of("READ_DOCS"), false);
        String token = jwtProvider.generateAccessToken(user, Collections.emptyMap());

        mockMvc.perform(get("/api/test/permission-write")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden());
    }
}
