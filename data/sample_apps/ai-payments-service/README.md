# AI Payments Service

Set `PAYMENT_PROVIDER_API_KEY` before running `mvn spring-boot:run`. `POST /api/payments/charges` creates an in-memory provider-simulation charge; `GET /api/payments/{id}` reads its status. It never sends a live charge.
