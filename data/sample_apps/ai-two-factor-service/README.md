# AI Two-Factor Service
Set `TWO_FACTOR_SERVICE_KEY` and `TWO_FACTOR_DEMO_CODE`, then run `mvn spring-boot:run`. A trusted authentication service calls `POST /internal/two-factor/verify` using `X-Two-Factor-Service-Key`. The configured code is a local demonstration seam; production requires a real TOTP/WebAuthn verifier and rate limiting.
