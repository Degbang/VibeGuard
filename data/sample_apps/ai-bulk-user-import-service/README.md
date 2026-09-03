# AI Bulk User Import Service
Set `BULK_IMPORT_ADMIN_KEY`, then run `mvn spring-boot:run`. Submit a newline-delimited `email,displayName` payload to `POST /internal/users/import` with `X-Bulk-Import-Key`.
