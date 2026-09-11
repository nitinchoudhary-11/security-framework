package com.dollop.app.otp;

/**
 * Contract for generating One-Time Passwords.
 */
public interface OtpGenerator {

    /**
     * Generates a random OTP.
     *
     * @param length the desired length of the OTP
     * @return the generated OTP string
     */
    String generate(int length);
}
