package com.dollop.app.user;

/**
 * Contract for loading a user's security profile.
 */
public interface PrincipalProvider {

    /**
     * Loads a principal by their local identifier (e.g., username or email).
     *
     * @param identifier the local identifier
     * @return the populated principal
     */
    SecurityPrincipal loadByIdentifier(String identifier);

    /**
     * Loads a principal based on an external OAuth2 provider's ID.
     *
     * @param provider the OAuth2 provider (e.g., "GOOGLE")
     * @param providerId the unique ID from the provider
     * @return the populated principal
     */
    SecurityPrincipal loadByOAuth2Id(String provider, String providerId);
}
