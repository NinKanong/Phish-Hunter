# Security

The application uses Argon2id password hashes, short-lived JWT access tokens, refresh tokens, HttpOnly/SameSite cookies, request trace IDs, upload limits, file signature checks, and an SSRF guard.

Before public deployment: set a strong `SECRET_KEY`, enable HTTPS, set secure cookies, configure trusted hosts, enable rate limiting at the reverse proxy, move storage off the local filesystem, configure backups, and isolate dynamic analysis infrastructure.
