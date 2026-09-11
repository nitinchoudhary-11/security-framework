package com.dollop.app.common;

import java.util.Map;

/**
 * Generalized contract for dispatching messages to users (Email, SMS, Push).
 */
public interface NotificationDispatcher {

    /**
     * Sends a notification to the specified destination.
     *
     * @param destination the recipient's identifier (email address, phone number)
     * @param type the type of notification
     * @param payload context data required to render or send the message
     */
    void send(String destination, NotificationType type, Map<String, Object> payload);
}
