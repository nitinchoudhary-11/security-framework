package com.dollop.app.user.model;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;

/**
 * Represents the state of a generated password reset request.
 */
@Value
@Builder
public class PasswordResetToken {

    /**
     * The secure, random string (or JWT) sent to the user.
     */
    private final String tokenValue;

    /**
     * The user who requested the reset.
     */
    private final String targetIdentifier;

    /**
     * When the token was created.
     */
    private final Instant createdAt;

    /**
     * When the token naturally expires.
     */
    private final Instant expiresAt;
}
