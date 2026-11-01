# Account Desk: Product Improvement Specs

These are proposed additions to improve administrator productivity, account security, and operational visibility. They are not currently implemented.

## Priorities

1. Audit log filters and CSV export
2. Multi-factor authentication for administrator accounts
3. Account detail view
4. Operational status panel
5. Administrator account invitations

## 1. Audit Log Filters and CSV Export

### Goal
Help administrators find and share relevant security or account events without paging through unrelated records.

### Requirements
- Add filters for date range, event type, actor, and affected account.
- Allow filters to be combined with the existing text search.
- Keep pagination and show the total number of matching events.
- Export the currently filtered results as CSV.
- Require administrator access for both viewing and exporting.
- Escape CSV fields correctly and exclude password hashes, session tokens, reset tokens, and other secrets.

### Acceptance criteria
- An administrator can narrow the log by one or more filters and reset the filters.
- Search, filtering, and pagination return consistent results and counts.
- CSV export contains the filtered events and is usable in common spreadsheet applications.
- Non-administrators cannot view or export audit data.

## 2. Administrator Multi-Factor Authentication

### Goal
Reduce the risk of administrator account takeover.

### Requirements
- Add a second factor for administrator sign-in, preferably passkeys or TOTP.
- Require additional verification before sensitive administrator actions when appropriate.
- Provide secure enrollment, recovery, and factor-removal flows.
- Store only the minimum protected material needed to verify the factor; never log recovery codes or secrets.
- Preserve the existing custom password/session architecture unless a separate migration to an identity provider is approved.

### Acceptance criteria
- An administrator cannot complete sign-in without the configured second factor.
- Enrollment and recovery require proof of account ownership.
- Recovery codes, if used, are single-use and stored safely.
- Security-sensitive factor changes are recorded in the audit log.
- Tests cover successful verification, invalid and replayed codes, recovery, and session behavior.

## 3. Account Detail View

### Goal
Give administrators the context needed to resolve account and security issues in one place.

### Requirements
- Open a detail view from an account search result.
- Show account identity, creation date, email-verification state, role, and status.
- Show recent relevant audit events and active sessions.
- Provide permitted actions such as resending verification email, revoking sessions, and changing status or role.
- Clearly confirm consequential actions and record every administrative change in the audit log.
- Enforce authorization on the server for every action; hiding controls in the browser is not access control.

### Acceptance criteria
- Only administrators can retrieve account details and perform administrative actions.
- The view displays current server-side state and handles deleted or unavailable accounts clearly.
- Session revocation and account changes take effect immediately.
- Actions are auditable and sensitive credential/token data is never displayed.

## 4. Operational Status Panel

### Goal
Make service and email-delivery problems visible before they disrupt account workflows. 

### Requirements
- Show database connectivity and a recent successful application health check.
- Show email transport configuration status and recent delivery failures without exposing SMTP credentials or message contents.
- Show backup status appropriate to the active backend: local SQLite backup information or Supabase-managed backup/PITR guidance.
- Restrict detailed operational information to administrators and avoid exposing internal diagnostics publicly.
- Provide actionable status labels and timestamps rather than raw secrets or stack traces.

### Acceptance criteria
- The panel distinguishes healthy, degraded, and unavailable states.
- Database and email checks have bounded timeouts and do not block normal account requests.
- No credentials, connection strings, message bodies, or sensitive database details are shown.
- Failure states are testable and do not disclose details to unauthenticated users.

## 5. Administrator Account Invitations

### Goal
Let administrators onboard users without asking them to use open registration or manually coordinate account setup.

### Requirements
- Allow an administrator to invite an email address.
- Send a short-lived, single-use invitation link using the configured email transport.
- Let the recipient choose a password and verify ownership of the invited address.
- Prevent invitations from bypassing normal account uniqueness, rate-limit, and abuse protections.
- Record invitation creation, acceptance, expiration, and cancellation in the audit log without recording raw tokens.

### Acceptance criteria
- Only administrators can issue or cancel invitations.
- Expired, used, or cancelled invitation links cannot create accounts.
- Invitation tokens are random, stored only as hashes, and never included in logs.
- Duplicate or already-registered addresses receive a safe, non-enumerating response.
- Tests cover invitation lifecycle, abuse limits, email failure, and audit events.

## Repository and Configuration Cleanup

- Resolve the merge-conflict markers in the workspace-level `README.md` and retain the useful setup information.
- Remove unused Supabase project URL/anon-key notes from `TODO.md`; the application README states that this server uses a private `DATABASE_URL` and does not use the project URL or anon key. Keep actual database credentials out of tracked files.
- Keep this document as a proposal until individual features are selected and implemented.
