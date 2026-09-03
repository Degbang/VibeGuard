# AI User Accounts Service

Run with `mvn spring-boot:run`. The API exposes `POST /api/users/signup`, `POST /api/users/login`, `GET /api/users/{id}`, and `PUT /api/users/{id}`. Passwords are stored only as BCrypt hashes in memory.
