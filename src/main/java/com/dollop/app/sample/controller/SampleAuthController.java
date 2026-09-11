package com.dollop.app.sample.controller;

import com.dollop.app.auth.model.AuthenticationResult;
import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.jwt.RefreshTokenService;
import com.dollop.app.spi.user.UserLookupProvider;
import com.dollop.app.user.SecurityPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

/**
 * Public REST Controller exposing login and refresh token endpoints.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class SampleAuthController {

    private final AuthenticationManager authenticationManager;
    private final UserLookupProvider userLookupProvider;
    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;

    public SampleAuthController(
            AuthenticationManager authenticationManager,
            UserLookupProvider userLookupProvider,
            JwtProvider jwtProvider,
            RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.userLookupProvider = userLookupProvider;
        this.jwtProvider = jwtProvider;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResult> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        SecurityPrincipal principal = userLookupProvider.findByIdentifier(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String accessToken = jwtProvider.generateAccessToken(principal, Collections.emptyMap());
        String refreshToken = jwtProvider.generateRefreshToken(principal);

        return ResponseEntity.ok(AuthenticationResult.builder()
                .principalIdentifier(principal.getIdentifier())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build());
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResult> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        AuthenticationResult result = refreshTokenService.refresh(refreshToken);
        return ResponseEntity.ok(result);
    }
}
