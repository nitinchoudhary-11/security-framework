package com.dollop.app.spi.auth;

import com.dollop.app.auth.model.AuthenticationRequest;

/**
 * Service Provider Interface allowing customization of actions when authentication fails.
 */
public interface AuthenticationFailureHandlerSpi {

    /**
     * Called upon an authentication failure.
     *
     * @param request the initial request attempt details
     * @param exceptionMessage the reason for the failure
     */
    void onAuthenticationFailure(AuthenticationRequest request, String exceptionMessage);
}
