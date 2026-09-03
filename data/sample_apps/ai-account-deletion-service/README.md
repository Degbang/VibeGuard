# AI Account Deletion Service
Set `ACCOUNT_API_KEY` and `ACCOUNT_OWNER_ID`, then run `mvn spring-boot:run`. The service only accepts `GET /api/accounts/{id}/export` and `DELETE /api/accounts/{id}` when the requested ID equals the authenticated owner's configured ID.
