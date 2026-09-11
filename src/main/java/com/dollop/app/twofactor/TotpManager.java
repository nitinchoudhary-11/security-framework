package com.dollop.app.twofactor;

/**
 * Manages Authenticator app setup and Time-based One Time Password validation.
 */
public interface TotpManager {

    /**
     * Generates a new Base32 encoded secret key for a user.
     *
     * @return the secret key
     */
    String generateSecret();

    /**
     * Generates the otpauth:// URI used to render a QR code for Authenticator apps.
     *
     * @param accountName the identifier of the user (e.g., email)
     * @param secret the generated secret
     * @return the provisioning URI
     */
    String getProvisioningUri(String accountName, String secret);

    /**
     * Verifies a TOTP code against the user's secret.
     *
     * @param secret the stored secret for the user
     * @param code the code provided by the user
     * @return true if valid
     */
    boolean verifyCode(String secret, String code);
}
