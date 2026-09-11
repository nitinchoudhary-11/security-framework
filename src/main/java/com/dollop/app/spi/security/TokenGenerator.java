package com.dollop.app.spi.security;

/**
 * Service Provider Interface for generating secure random strings.
 */
public interface TokenGenerator {

    /**
     * Generates a cryptographically secure random string.
     *
     * @param length the desired length
     * @return the random string
     */
    String generateToken(int length);
}
