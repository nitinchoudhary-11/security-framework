package com.dollop.app.jwt;

import com.dollop.app.user.SecurityPrincipal;
import java.util.Map;

/**
 * Handles the generation of JWT access and refresh tokens.
 */
public interface JwtProvider {

    /**
     * Generates a new access token for the given principal.
     *
     * @param principal the authenticated user
     * @param customClaims additional claims to inject into the payload
     * @return the encoded JWT string
     */
    String generateAccessToken(SecurityPrincipal principal, Map<String, Object> customClaims);

    /**
     * Generates a longer-lived refresh token for the given principal.
     *
     * @param principal the authenticated user
     * @return the encoded JWT string
     */
    String generateRefreshToken(SecurityPrincipal principal);
}
