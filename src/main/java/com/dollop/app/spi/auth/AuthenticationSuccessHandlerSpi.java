package com.dollop.app.spi.auth;

import com.dollop.app.auth.model.AuthenticationResult;

/**
 * Service Provider Interface allowing customization of actions immediately following a successful login.
 */
public interface AuthenticationSuccessHandlerSpi {

    /**
     * Called upon successful authentication.
     *
     * @param result the result containing generated tokens
     */
    void onAuthenticationSuccess(AuthenticationResult result);
}
