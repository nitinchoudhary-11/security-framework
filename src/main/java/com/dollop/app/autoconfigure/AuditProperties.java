package com.dollop.app.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for asynchronous security event logging.
 */
@ConfigurationProperties(prefix = "security.audit")
public class AuditProperties {

    /**
     * Whether the audit module is enabled.
     */
    private boolean enabled = true;

    /**
     * Whether to log events to the console by default.
     */
    private boolean logToConsole = true;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isLogToConsole() {
        return logToConsole;
    }

    public void setLogToConsole(boolean logToConsole) {
        this.logToConsole = logToConsole;
    }
}
