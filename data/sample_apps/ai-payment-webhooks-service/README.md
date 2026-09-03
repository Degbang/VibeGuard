# AI Payment Webhooks Service
Set `PAYMENT_WEBHOOK_SECRET`, then run `mvn spring-boot:run`. Send `POST /webhooks/payments` with an HMAC-SHA256 `X-Payment-Signature` header; received events are held in memory.
