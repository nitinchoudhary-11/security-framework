package com.dollop.app.sample.controller;

import com.dollop.app.spi.user.CurrentUserResolver;
import com.dollop.app.user.SecurityPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Protected REST Controller demonstrating framework method security annotations.
 */
@RestController
@RequestMapping("/api/v1/resources")
public class SampleResourceController {

    private final CurrentUserResolver currentUserResolver;

    public SampleResourceController(CurrentUserResolver currentUserResolver) {
        this.currentUserResolver = currentUserResolver;
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser() {
        return currentUserResolver.resolveCurrentUser()
                .map(user -> ResponseEntity.ok(Map.<String, Object>of(
                        "identifier", user.getIdentifier(),
                        "authorities", user.getAuthorities(),
                        "authProvider", user.getAuthProvider()
                )))
                .orElse(ResponseEntity.status(401).build());
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> adminEndpoint() {
        return ResponseEntity.ok(Map.of("message", "Access granted to ADMIN role"));
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, String>> userEndpoint() {
        return ResponseEntity.ok(Map.of("message", "Access granted to USER role (and inherited by ADMIN)"));
    }

    @GetMapping("/reports")
    @PreAuthorize("hasAuthority('REPORTS_EXPORT')")
    public ResponseEntity<Map<String, String>> exportReports() {
        return ResponseEntity.ok(Map.of("message", "Access granted to REPORTS_EXPORT authority"));
    }

    @GetMapping("/document/write")
    @PreAuthorize("hasPermission('document', 'write')")
    public ResponseEntity<Map<String, String>> writeDocument() {
        return ResponseEntity.ok(Map.of("message", "Access granted by ResourcePermissionEvaluator for document:write"));
    }
}
