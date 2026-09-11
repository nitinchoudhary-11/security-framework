package com.dollop.app.spi.sms;

import lombok.Builder;
import lombok.Value;

/**
 * Value object encapsulating all data needed to send an SMS.
 */
@Value
@Builder
public class SmsMessage {
    private final String phoneNumber;
    private final String text;
}
