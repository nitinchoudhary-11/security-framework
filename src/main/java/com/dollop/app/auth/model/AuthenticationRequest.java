package com.dollop.app.auth.model;

import lombok.Builder;
import lombok.Value;

import java.util.Map;

/**
 * Represents the raw, incoming data required to attempt authentication.
 * Designed as an immutable value object.
 */
@Value
@Builder
public class AuthenticationRequest {

    /**
     * The username, email, or OAuth2 subject ID. Required to locate the principal.
     */
    private final String identifier;

    /**
     * The raw password or OAuth2 access token.
     */
    private final String credentials;

    /**
     * The IP address of the requester (useful for audit logging and risk-based authentication).
     */
    private final String clientIp;

    /**
     * Additional metadata for capturing things like User-Agent, Device ID, or reCAPTCHA tokens.
     */
    private final Map<String, String> additionalMetadata;
}
