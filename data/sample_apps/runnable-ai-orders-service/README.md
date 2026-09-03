# Runnable AI Orders Service

A compact Spring Boot 3 / Java 17 orders API generated as a runnable
microservice sample for VibeGuard. It stores orders in memory, validates input,
and requires HTTP Basic authentication.

## Run locally

```bash
export SPRING_SECURITY_USER_NAME=demo
export SPRING_SECURITY_USER_PASSWORD=use-a-local-password
mvn spring-boot:run
```

The service starts at `http://localhost:8080`.

## Try the API

```bash
curl -u "$SPRING_SECURITY_USER_NAME:$SPRING_SECURITY_USER_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d '{"productCode":"NOTEBOOK-A5","quantity":2}' \
  http://localhost:8080/api/orders

curl -u "$SPRING_SECURITY_USER_NAME:$SPRING_SECURITY_USER_PASSWORD" \
  http://localhost:8080/api/orders/1
```

## Test and package

```bash
mvn verify
docker build -t runnable-ai-orders-service .
docker run --rm -p 8080:8080 \
  -e SPRING_SECURITY_USER_NAME=demo \
  -e SPRING_SECURITY_USER_PASSWORD=use-a-local-password \
  runnable-ai-orders-service
```

This is a teaching sample, not a production order system: it has no database,
payment integration, or persistent identity store.
