package com.dollop.app.auth.model;

import lombok.Builder;
import lombok.Value;

/**
 * Represents the outcome of a successful authentication attempt.
 */
@Value
@Builder
public class AuthenticationResult {

    /**
     * The unique identifier of the authenticated user.
     */
    private final String principalIdentifier;

    /**
     * The short-lived JWT for API access.
     */
    private final String accessToken;

    /**
     * The long-lived token to acquire new access tokens.
     */
    private final String refreshToken;

    /**
     * Indicates if the login flow is paused pending an OTP/2FA challenge.
     */
    private final boolean mfaRequired;

    /**
     * How long the accessToken is valid for.
     */
    private final long expiresInSeconds;
}
