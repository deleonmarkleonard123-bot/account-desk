# Account Desk

## Configuration

Copy `.env.example` to `.env`. It documents the runtime settings:

- `HOST`, `PORT`: Node bind address and port. Production should use `127.0.0.1` behind Caddy.
- `DB_BACKEND`: `sqlite` for local development/tests or `postgres` for Supabase Postgres.
- `DB_PATH`: SQLite file path when using the local backend; defaults to `data/accounts.sqlite`.
- `DATABASE_URL`, `DATABASE_POOL_SIZE`: server-only Supabase Postgres session-pooler connection string and pool limit. Never put this value in browser code or commit it.
- `AUTH_BACKEND`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`: Supabase Auth configuration. The service-role key is server-only and must never be exposed to the browser or committed.
- `NODE_ENV`, `APP_BASE_URL`: environment and externally visible app URL.
- `TRUST_PROXY`: enable forwarded HTTPS/client-IP headers only behind a trusted proxy.
- `RATE_LIMIT_*`: fixed-window length and per-IP/per-email request limits.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM`: legacy account-email settings used only when `AUTH_BACKEND=legacy`.

## Email setup

Production uses Supabase Auth email delivery. Configure the SMTP provider under **Supabase → Authentication → SMTP Settings**, set the project's Site URL to `APP_BASE_URL`, and add the app URL to the Auth redirect URL allowlist. Supabase Auth sends signup confirmations, recovery links, and invites through that SMTP configuration. Keep all app environment values private; `.env` is ignored by Git.

## Supabase Database

In Supabase, open **Project Settings → Database → Connection string**, choose the **Session pooler** connection string, and set it as `DATABASE_URL` in the server's private `.env`. URL-encode special characters in the database password. Download the database root certificate from **Project Settings → Database → SSL Configuration**, save it locally, and set `DATABASE_SSL_CA` to its path; TLS verification stays enabled. Set `DB_BACKEND=postgres`. `SUPABASE_URL` and `SUPABASE_ANON_KEY` configure Auth API access; the service-role key is privileged and must remain server-only. Keep all keys and database credentials out of Git, browser code, and chat. On startup, the server applies the idempotent schema in `supabase/migrations/` and verifies the database connection. Local development and tests use SQLite by default.

The production application uses Supabase Auth for passwords, email verification, password recovery, and provider sessions. Account profiles, roles, status, audit events, app-level administrator MFA, and revocable app sessions remain in private tables accessed only by the Node server through its PostgreSQL connection. User-to-profile mapping is stored in server-managed Supabase `app_metadata`; authorization still comes from the private profile table.

## Migrating Accounts to Supabase Auth

Existing custom password hashes use scrypt and cannot be reused by Supabase Auth. Set `AUTH_BACKEND=supabase`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` in the server's private environment. Confirm Supabase Auth email confirmations are enabled, SMTP is configured, `APP_BASE_URL` is set as the Site URL, and the URL is in the redirect allowlist. The service-role key must remain server-only.

Run `npm run auth:migrate` for a dry run, then `npm run auth:migrate -- --apply` to link existing profiles, send password setup invitations, and clear obsolete local password hashes as each account migrates. Back up the database first. Existing users must follow the setup email to choose a new password. Do not switch production traffic to Supabase Auth until migration completes and a test user can confirm email, sign in, reset a password, and access the correct role.

To move the current SQLite accounts and related tokens, sessions, rate limits, and audit history into an empty Supabase database, set `DATABASE_URL` in `.env`, stop the local app, then run `npm run db:migrate-supabase`. The importer refuses to write into a non-empty Supabase database. After confirming the import, set `DB_BACKEND=postgres` and restart. Keep the SQLite file and a verified backup until the Supabase copy has been checked. The `db:backup` and `db:restore` scripts are SQLite-only; use Supabase's managed backup/PITR tools when Postgres is active.

Start the app with `npm start`. In legacy mode, verification and reset links are one-time app tokens. In Supabase mode, Supabase Auth owns token expiry and email delivery. Local tests default to legacy mode; production startup requires Supabase Auth configuration.

## Abuse protections

Sign-in, registration, and password-reset requests use database-backed fixed-window limits. Configure their window and per-IP/per-email maxima with the `RATE_LIMIT_*` variables in `.env.example`. The default session cookie is `HttpOnly` and `SameSite=Strict`; it gains `Secure` on direct HTTPS requests. Set `TRUST_PROXY=true` only when the app is reachable exclusively through a trusted reverse proxy that sets `X-Forwarded-Proto` and `X-Forwarded-For`.

## Checks

Run `npm test` to exercise permissions, account lifecycle, email recovery, sessions, audit events, abuse throttling, cookie flags, and backup/restore against temporary SQLite databases and a local SMTP test server. It also checks production startup configuration.

## Admin Setup

Register the intended administrator through the app first, then promote that existing account once:

```sh
npm run promote-admin -- admin@your-domain.example
```

Promotion is one-time per database. The admin account dashboard and read-only activity log require administrator sign-in.

## Database Backup

The live database defaults to `data/accounts.sqlite`; set `DB_PATH` to use another location. Create a verified, non-overwriting online backup with:

```sh
npm run db:backup -- ./data/backups/accounts-$(date +%Y%m%d-%H%M%S).sqlite
```

Restore a backup to a new file, which is integrity-checked before and after the copy:

```sh
npm run db:restore -- ./data/backups/accounts-20261031-120000.sqlite ./data/accounts-restored.sqlite
```

To switch to the restored file, stop the app, preserve the current database, set `DB_PATH` to the restored file, and restart. Keep backups encrypted and access-controlled; they contain account data. Never restore over a database file that the app is using.

## HTTPS Deployment

The Node server speaks HTTP and must not be exposed directly to the internet in production. Point a DNS name at the server, install Caddy, and use the included `Caddyfile`; Caddy obtains and renews TLS certificates when ports 80 and 443 are reachable. Keep Node bound to `127.0.0.1:3000`, with the app behind Caddy only.

For production, set `NODE_ENV=production`, `AUTH_BACKEND=supabase`, `HOST=127.0.0.1`, `PORT=3000`, `APP_BASE_URL=https://your-domain.example`, `TRUST_PROXY=true`, Supabase Auth settings, and the private Postgres connection. The app refuses to start without an HTTPS base URL, trusted-proxy mode, and Supabase Auth configuration. Only enable `TRUST_PROXY` when direct access to the Node port is blocked and the proxy overwrites forwarded headers.

Start the app under a process manager, then run Caddy with `DOMAIN=your-domain.example caddy run --config Caddyfile`. Promote the initial admin after registering its account with `npm run promote-admin -- admin@your-domain.example`. Verify the deployment with `curl -I https://your-domain.example` and confirm plain HTTP redirects to HTTPS. Public deployment still requires a real domain, DNS, a host, and SMTP credentials.

## Render Deployment

The repository includes a Render Blueprint at its root. Connect the repository to Render and create a Blueprint; it builds and runs the app from `mlad-node-project/`. The Blueprint uses Render's free instance tier for initial validation, which may spin down while idle. Select a paid instance in Render if the app needs consistent availability.

Set the prompted `APP_BASE_URL` to the HTTPS URL assigned by Render. Enter the Supabase session-pooler `DATABASE_URL`, Supabase project URL, anon key, and service-role key as private environment values. Configure SMTP in the Supabase Auth dashboard and allow the Render URL as an Auth redirect. Upload the Supabase database root certificate as a Render secret file named `supabase-ca.crt`; the Blueprint points `DATABASE_SSL_CA` at `/etc/secrets/supabase-ca.crt`. Do not commit the certificate or credentials. Render supplies HTTPS and the listening port; the service binds to `0.0.0.0` and trusts Render's reverse proxy.

After the first successful deploy, register the intended administrator and run `npm run promote-admin -- admin@your-domain.example` from the Render Shell or a trusted local environment configured for the same Supabase database. Verify registration, verification email delivery, and sign-in before sharing the URL publicly.