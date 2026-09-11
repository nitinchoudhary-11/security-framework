package com.dollop.app.spi.email;

import lombok.Builder;
import lombok.Value;

/**
 * Value object encapsulating all data needed to send an email.
 */
@Value
@Builder
public class EmailMessage {
    private final String to;
    private final String subject;
    private final String body;
    private final boolean html;
}
