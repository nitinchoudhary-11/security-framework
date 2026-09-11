package com.dollop.app.common.model;

import com.dollop.app.common.NotificationType;
import lombok.Builder;
import lombok.Value;

import java.util.Map;

/**
 * The payload handed to the NotificationDispatcher containing everything needed to render and send a message.
 */
@Value
@Builder
public class NotificationMessage {

    /**
     * The email address or phone number.
     */
    private final String destination;

    /**
     * Enum indicating the reason for the notification.
     */
    private final NotificationType type;

    /**
     * Optional subject line for email notifications.
     */
    private final String subject;

    /**
     * The raw or templated text to send.
     */
    private final String body;

    /**
     * Variables to inject into a templating engine (e.g., otpCode, resetLink).
     */
    private final Map<String, Object> templateVariables;
}
