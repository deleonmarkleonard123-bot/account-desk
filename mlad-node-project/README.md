# Account Desk

## Configuration

Copy `.env.example` to `.env`. It documents the runtime settings:

- `HOST`, `PORT`: Node bind address and port. Production should use `127.0.0.1` behind Caddy.
- `DB_BACKEND`: `sqlite` for local development/tests or `postgres` for Supabase Postgres.
- `DB_PATH`: SQLite file path when using the local backend; defaults to `data/accounts.sqlite`.
- `DATABASE_URL`, `DATABASE_POOL_SIZE`: server-only Supabase Postgres session-pooler connection string and pool limit. Never put this value in browser code or commit it.
- `NODE_ENV`, `APP_BASE_URL`: environment and externally visible app URL.
- `TRUST_PROXY`: enable forwarded HTTPS/client-IP headers only behind a trusted proxy.
- `RATE_LIMIT_*`: fixed-window length and per-IP/per-email request limits.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM`: account email delivery settings.

## Email setup

Copy `.env.example` to `.env`, then set the SMTP host, port, username, password, sender address, and `APP_BASE_URL` for your mail provider and deployment. Use port `587` with `SMTP_SECURE=false` for STARTTLS, or port `465` with `SMTP_SECURE=true` for implicit TLS. Keep `.env` private; it is ignored by Git.

## Supabase Database

In Supabase, open **Project Settings → Database → Connection string**, choose the **Session pooler** connection string, and set it as `DATABASE_URL` in the server's private `.env`. URL-encode special characters in the database password. Download the database root certificate from **Project Settings → Database → SSL Configuration**, save it locally, and set `DATABASE_SSL_CA` to its path; TLS verification stays enabled. Set `DB_BACKEND=postgres`. The project URL and anon key are not database credentials and are not used by this server; keep database credentials out of `TODO.md`, Git, client JavaScript, and chat. On startup, the server applies the idempotent schema in `supabase/migrations/` and verifies the database connection. Local development and tests use SQLite by default.

The current application uses its own password/session system, not Supabase Auth. The Supabase database stores the account hashes and session/token tables; it is accessed only by the Node server through the private PostgreSQL connection.

To move the current SQLite accounts and related tokens, sessions, rate limits, and audit history into an empty Supabase database, set `DATABASE_URL` in `.env`, stop the local app, then run `npm run db:migrate-supabase`. The importer refuses to write into a non-empty Supabase database. After confirming the import, set `DB_BACKEND=postgres` and restart. Keep the SQLite file and a verified backup until the Supabase copy has been checked. The `db:backup` and `db:restore` scripts are SQLite-only; use Supabase's managed backup/PITR tools when Postgres is active.

Start the app with `npm start`. Email verification links expire after 24 hours. Password-reset links expire after 15 minutes. Both use random tokens stored only as SHA-256 hashes and can only be used once. In development without SMTP settings, links are printed to the server console. Production mode requires SMTP configuration.

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

For production, set `NODE_ENV=production`, `HOST=127.0.0.1`, `PORT=3000`, `APP_BASE_URL=https://your-domain.example`, `TRUST_PROXY=true`, and valid `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, and `MAIL_FROM` values in `.env`. The app refuses to start in production without an HTTPS base URL, trusted-proxy mode, and SMTP configuration. Only enable `TRUST_PROXY` when direct access to the Node port is blocked and the proxy overwrites forwarded headers.

Start the app under a process manager, then run Caddy with `DOMAIN=your-domain.example caddy run --config Caddyfile`. Promote the initial admin after registering its account with `npm run promote-admin -- admin@your-domain.example`. Verify the deployment with `curl -I https://your-domain.example` and confirm plain HTTP redirects to HTTPS. Public deployment still requires a real domain, DNS, a host, and SMTP credentials.