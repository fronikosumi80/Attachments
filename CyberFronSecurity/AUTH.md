# CyberFronSecurity authentication

The project includes a small reference auth API in `auth/server.cjs`.

## Local development

```powershell
node auth/server.cjs
```

It listens on `127.0.0.1:4317`. The packaged Electron app starts the same API on an ephemeral loopback port and stores its user data under the OS application-data directory. Passwords are hashed with Node `crypto.scrypt`; they are never written as plain text. Sessions are random opaque bearer tokens with a 30-day expiry, and login attempts are rate limited per IP/email pair.

## Production requirements

Run the API behind a real HTTPS reverse proxy and set `AUTH_ORIGIN` to the exact website origin. Replace the example API base in `index.js` with the deployed HTTPS API URL. Use a managed database, encrypted backups, a transactional email provider for password reset links, key rotation, audit logging, CSRF protection for cookie sessions, and a secrets manager before production release.

The password-reset endpoint intentionally does not reveal whether an email exists. It currently returns a generic response because no email provider is configured; it does not issue a fake reset token.
