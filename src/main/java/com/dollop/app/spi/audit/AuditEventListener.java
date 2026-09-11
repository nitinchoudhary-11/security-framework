package com.dollop.app.spi.audit;

import com.dollop.app.audit.model.SecurityEvent;

/**
 * Service Provider Interface allowing consuming applications to listen and react to framework security events.
 */
public interface AuditEventListener {

    /**
     * Called whenever a security event (e.g., LOGIN_SUCCESS, ACCESS_DENIED) is published.
     *
     * @param event the detailed security event
     */
    void onSecurityEvent(SecurityEvent event);
}
