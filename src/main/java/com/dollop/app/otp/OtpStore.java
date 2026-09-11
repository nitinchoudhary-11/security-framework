package com.dollop.app.otp;

/**
 * Temporary storage mechanism to hold an OTP until validation.
 */
public interface OtpStore {

    /**
     * Stores the OTP for a specific identifier.
     *
     * @param identifier the user identifier (e.g., email or phone)
     * @param otpCode the code to store
     * @param expirationSeconds the lifetime of the code
     */
    void store(String identifier, String otpCode, long expirationSeconds);

    /**
     * Verifies the provided code against the stored code.
     *
     * @param identifier the user identifier
     * @param otpCode the code to check
     * @return true if the code matches and hasn't expired
     */
    boolean verify(String identifier, String otpCode);
}
