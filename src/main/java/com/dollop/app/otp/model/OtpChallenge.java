package com.dollop.app.otp.model;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;

/**
 * Represents an active, unverified OTP request.
 */
@Value
@Builder
public class OtpChallenge {

    /**
     * A unique correlation ID to track the attempt across requests.
     */
    private final String challengeId;

    /**
     * The user the OTP belongs to.
     */
    private final String identifier;

    /**
     * Masked destination (e.g., ***@gmail.com) to return safely to the client UI.
     */
    private final String maskedDestination;

    /**
     * The exact time the OTP becomes invalid.
     */
    private final Instant expiresAt;
}
