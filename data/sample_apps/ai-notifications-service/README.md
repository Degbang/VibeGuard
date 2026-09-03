# AI Notifications Service

Set `NOTIFICATION_WEBHOOK_URL` and `NOTIFICATION_WEBHOOK_SIGNING_SECRET`, then run `mvn spring-boot:run`. `POST /internal/notifications/test` sends a signed JSON webhook. The endpoint is intended for an internal network or gateway.
