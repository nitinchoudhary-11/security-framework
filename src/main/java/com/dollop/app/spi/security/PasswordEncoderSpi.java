package com.dollop.app.spi.security;

/**
 * Service Provider Interface to decouple password encoding logic.
 */
public interface PasswordEncoderSpi {

    /**
     * Encodes a raw password.
     *
     * @param rawPassword the plain text password
     * @return the hashed password
     */
    String encode(String rawPassword);

    /**
     * Validates a raw password against an encoded hash.
     *
     * @param rawPassword the plain text password
     * @param encodedPassword the hashed password stored in the system
     * @return true if the passwords match
     */
    boolean matches(String rawPassword, String encodedPassword);
}
