package com.dollop.app.user;

/**
 * Manages the lifecycle of secure, time-limited tokens for password recovery.
 */
public interface PasswordResetManager {

    /**
     * Generates a secure, time-limited token for resetting a password.
     *
     * @param identifier the user's identifier
     * @return the secure reset token string
     */
    String generateResetToken(String identifier);

    /**
     * Validates a previously generated reset token.
     *
     * @param identifier the user's identifier
     * @param token the token to validate
     * @return true if valid and unexpired
     */
    boolean validateResetToken(String identifier, String token);
}
