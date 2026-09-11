package com.dollop.app.spi.email;

/**
 * Service Provider Interface for sending emails.
 */
public interface EmailService {

    /**
     * Dispatches an email message.
     *
     * @param message the email details
     */
    void sendEmail(EmailMessage message);
}
