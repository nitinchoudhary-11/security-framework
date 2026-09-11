package com.dollop.app.audit.model;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;

/**
 * A generic representation of a security-relevant action occurring in the system.
 */
@Value
@Builder
public class SecurityEvent {

    /**
     * A unique UUID for the event.
     */
    private final String eventId;

    /**
     * The type of security event.
     */
    private final SecurityEventType eventType;

    /**
     * The user involved (if known).
     */
    private final String principalIdentifier;

    /**
     * The origin of the request.
     */
    private final String ipAddress;

    /**
     * When the event occurred.
     */
    private final Instant timestamp;

    /**
     * Additional context (e.g., "Invalid password", "Missing MFA").
     */
    private final String details;
}
