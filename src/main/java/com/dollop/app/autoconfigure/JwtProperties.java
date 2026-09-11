package com.dollop.app.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for JSON Web Tokens.
 */
@ConfigurationProperties(prefix = "security.jwt")
public class JwtProperties {

    /**
     * The secret key used for signing access tokens (minimum 256-bit / 32 characters).
     * Required when JWT support is enabled.
     */
    private String accessSecret;

    /**
     * The secret key used for signing refresh tokens (minimum 256-bit / 32 characters).
     * Must differ from {@code accessSecret}. Required when JWT support is enabled.
     */
    private String refreshSecret;

    /**
     * Expiration time for access tokens in minutes.
     */
    private int accessTokenExpirationMinutes = 15;

    /**
     * Expiration time for refresh tokens in days.
     */
    private int refreshTokenExpirationDays = 7;

    /**
     * The issuer claim for generated tokens.
     */
    private String issuer = "security-framework";

    /**
     * Name of the HttpOnly cookie from which the JWT access token is read.
     * When {@code null} or blank, cookie-based token extraction is disabled.
     * Configure to opt-in to cookie transport (Phase 6 Decision #7).
     */
    private String cookieName;

    public String getAccessSecret() {
        return accessSecret;
    }

    public void setAccessSecret(String accessSecret) {
        this.accessSecret = accessSecret;
    }

    public String getRefreshSecret() {
        return refreshSecret;
    }

    public void setRefreshSecret(String refreshSecret) {
        this.refreshSecret = refreshSecret;
    }

    public String getCookieName() {
        return cookieName;
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public int getAccessTokenExpirationMinutes() {
        return accessTokenExpirationMinutes;
    }

    public void setAccessTokenExpirationMinutes(int accessTokenExpirationMinutes) {
        this.accessTokenExpirationMinutes = accessTokenExpirationMinutes;
    }

    public int getRefreshTokenExpirationDays() {
        return refreshTokenExpirationDays;
    }

    public void setRefreshTokenExpirationDays(int refreshTokenExpirationDays) {
        this.refreshTokenExpirationDays = refreshTokenExpirationDays;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
