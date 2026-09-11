package com.dollop.app.audit.model;

/**
 * Defines standard security events captured by the framework.
 */
public enum SecurityEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    TOKEN_REFRESH,
    ACCESS_DENIED,
    PASSWORD_CHANGED,
    ACCOUNT_LOCKED
}
