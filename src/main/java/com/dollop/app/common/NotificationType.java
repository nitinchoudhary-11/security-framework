package com.dollop.app.common;

/**
 * Defines the types of notifications the framework can dispatch.
 */
public enum NotificationType {
    /**
     * One-Time Password for login or verification.
     */
    OTP,

    /**
     * A secure link or code for password recovery.
     */
    PASSWORD_RESET,

    /**
     * A security alert (e.g., suspicious login attempt).
     */
    SECURITY_ALERT
}
