package com.dollop.app.spi.sms;

/**
 * Service Provider Interface for sending SMS text messages.
 */
public interface SmsService {

    /**
     * Dispatches an SMS message.
     *
     * @param message the SMS details
     */
    void sendSms(SmsMessage message);
}
