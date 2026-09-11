package com.dollop.app.spi.auth;

import com.dollop.app.otp.model.OtpChallenge;

/**
 * Service Provider Interface for safely formatting and dispatching OTP challenges.
 */
public interface OtpSender {

    /**
     * Sends the OTP associated with the given challenge to the user.
     *
     * @param challenge the active OTP challenge
     * @param plainTextOtp the raw, unmasked OTP to send
     */
    void sendOtp(OtpChallenge challenge, String plainTextOtp);
}
