package com.dollop.app.spi.notification;

import com.dollop.app.common.model.NotificationMessage;

/**
 * Service Provider Interface for routing general notification messages.
 */
public interface NotificationSender {

    /**
     * Routes and sends the given notification to the appropriate underlying service (Email, SMS, etc.).
     *
     * @param message the notification payload
     */
    void send(NotificationMessage message);
}
