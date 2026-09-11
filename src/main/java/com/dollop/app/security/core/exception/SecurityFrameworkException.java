package com.dollop.app.security.core.exception;

public class SecurityFrameworkException extends RuntimeException {

    private final int status;

    public SecurityFrameworkException(String message, int status) {
        super(message);
        this.status = status;
    }

    public SecurityFrameworkException(String message, Throwable cause, int status) {
        super(message, cause);
        this.status = status;
    }

    public int getStatus() {
        return status;
    }
}
