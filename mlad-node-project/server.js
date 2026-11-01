const http = require('node:http');
const { createHash, createHmac, randomBytes, scrypt: scryptCallback, timingSafeEqual } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const { DatabaseSync } = require('node:sqlite');
const { Pool } = require('pg');
const { promisify } = require('node:util');
const fs = require('node:fs/promises');
const path = require('node:path');
const nodemailer = require('nodemailer');
require('dotenv').config();

const scrypt = promisify(scryptCallback);
const root = __dirname;
const dataDirectory = path.join(root, 'data');
const databaseFile = path.resolve(process.env.DB_PATH || path.join(dataDirectory, 'accounts.sqlite'));
const dataFile = process.env.DB_PATH ? `${databaseFile}.json` : path.join(dataDirectory, 'accounts.json');
const sessionLifetime = 12 * 60 * 60 * 1000;
const passwordLength = 64;
const maxBodySize = 16 * 1024;
const verificationLifetime = 24 * 60 * 60 * 1000;
const resetLifetime = 15 * 60 * 1000;
const inviteLifetime = 3 * 24 * 60 * 60 * 1000;
const rateLimitWindowMs = positiveIntegerSetting('RATE_LIMIT_WINDOW_MS', 15 * 60 * 1000);
let database;
let postgresPool;
let queries;
let mailTransport;
let dummyPasswordCredentials;
const transactionStorage = new AsyncLocalStorage();

function normalizeDatabaseRow(row) {
	if (!row) return row;
	for (const key of ['count', 'event_id', 'created_at', 'expires_at', 'attempts', 'window_started_at']) {
		const value = row[key];
		if (typeof value === 'string' && /^-?\d+$/.test(value)) row[key] = Number(value);
	}
	return row;
}

function postgresPlaceholders(sql) {
	let index = 0;
	return sql.replace(/\?/g, () => `$${++index}`);
}

function normalizedPostgresConnectionString() {
	const connectionString = new URL(process.env.DATABASE_URL);
	for (const option of ['sslmode', 'sslcert', 'sslkey', 'sslrootcert']) connectionString.searchParams.delete(option);
	return connectionString.toString();
}

async function postgresSslConfig() {
	const ssl = { rejectUnauthorized: true };
	if (process.env.DATABASE_SSL_CA) {
		ssl.ca = await fs.readFile(path.resolve(root, process.env.DATABASE_SSL_CA), 'utf8');
	}
	return ssl;
}

async function executeQuery(sql, execution = { mode: 'run', values: [] }) {
	const params = execution.values || execution;
	if (postgresPool) {
		const client = transactionStorage.getStore() || postgresPool;
		const result = await client.query(postgresPlaceholders(sql), params);
		return { rows: result.rows.map(normalizeDatabaseRow), rowCount: result.rowCount };
	}
	const statement = database.prepare(sql);
	if (execution.mode === 'all') return { rows: statement.all(...params), rowCount: 0 };
	if (execution.mode === 'get') {
		const row = statement.get(...params);
		return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
	}
	const result = statement.run(...params);
	return { rows: [], rowCount: Number(result.changes) };
}

function prepareQuery(sql) {
	return {
		get: async (...params) => (await executeQuery(sql, { mode: 'get', values: params })).rows[0],
		all: async (...params) => (await executeQuery(sql, { mode: 'all', values: params })).rows,
		run: async (...params) => executeQuery(sql, { mode: 'run', values: params })
	};
}

async function executeScript(sql) {
	if (postgresPool) return postgresPool.query(sql);
	return database.exec(sql);
}

function buildQueries() {
	const contains = column => postgresPool
		? `POSITION(LOWER(?) IN LOWER(${column})) > 0`
		: `instr(lower(${column}), lower(?)) > 0`;
	const auditSearch = `(? = '' OR ${contains('action')}
		OR ${contains('actor_email')}
		OR ${contains('affected_email')}
		OR ${contains("COALESCE(actor_account_id, '')")}
		OR ${contains("COALESCE(affected_account_id, '')")})`;
	const accountSearch = `(? = '' OR ${contains('display_name')} OR ${contains('email')})`;

	return {
		findById: prepareQuery('SELECT * FROM accounts WHERE id = ?'),
		findByEmail: prepareQuery('SELECT * FROM accounts WHERE lower(email) = lower(?)'),
		findActiveInvitationByEmail: prepareQuery('SELECT * FROM account_tokens WHERE purpose = ? AND lower(email) = lower(?) AND used_at IS NULL AND expires_at > ? ORDER BY expires_at DESC LIMIT 1'),
		deleteInvitationByEmail: prepareQuery("UPDATE account_tokens SET expires_at = ? WHERE purpose = 'invite' AND lower(email) = lower(?) AND used_at IS NULL"),
		findMfaSecret: prepareQuery('SELECT * FROM mfa_secrets WHERE account_id = ?'),
		insertMfaSecret: prepareQuery(`
			INSERT INTO mfa_secrets (account_id, secret, enabled, created_at)
			VALUES (?, ?, ?, ?)
		`),
		updateMfaSecret: prepareQuery('UPDATE mfa_secrets SET secret = ?, created_at = ? WHERE account_id = ?'),
		enableMfaSecret: prepareQuery('UPDATE mfa_secrets SET enabled = TRUE WHERE account_id = ?'),
		deleteMfaSecret: prepareQuery('DELETE FROM mfa_secrets WHERE account_id = ?'),
		insert: prepareQuery(`
			INSERT INTO accounts (id, email, display_name, created_at, role, status, salt, password_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`),
		update: prepareQuery('UPDATE accounts SET display_name = ? WHERE id = ?'),
		updatePendingEmail: prepareQuery('UPDATE accounts SET pending_email = ? WHERE id = ?'),
		verifyEmail: prepareQuery('UPDATE accounts SET email = ?, pending_email = NULL, email_verified_at = ? WHERE id = ?'),
		updatePassword: prepareQuery('UPDATE accounts SET salt = ?, password_hash = ? WHERE id = ?'),
		updateRole: prepareQuery('UPDATE accounts SET role = ? WHERE id = ?'),
		updateStatus: prepareQuery('UPDATE accounts SET status = ? WHERE id = ?'),
		delete: prepareQuery('DELETE FROM accounts WHERE id = ?'),
		count: prepareQuery('SELECT COUNT(*) AS count FROM accounts'),
		adminCount: prepareQuery("SELECT COUNT(*) AS count FROM accounts WHERE role = 'admin'"),
		activeAdminCount: prepareQuery("SELECT COUNT(*) AS count FROM accounts WHERE role = 'admin' AND status = 'active'"),
		findEmailOwner: prepareQuery('SELECT id FROM accounts WHERE (lower(email) = lower(?) OR lower(pending_email) = lower(?)) AND id <> ?'),
		insertSession: prepareQuery(`
			INSERT INTO sessions (session_id, token_hash, account_id, created_at, expires_at, user_agent)
			VALUES (?, ?, ?, ?, ?, ?)
		`),
		findSessionByToken: prepareQuery('SELECT * FROM sessions WHERE token_hash = ?'),
		deleteSessionByToken: prepareQuery('DELETE FROM sessions WHERE token_hash = ?'),
		listSessions: prepareQuery('SELECT * FROM sessions WHERE account_id = ? AND expires_at > ? ORDER BY created_at DESC'),
		listAccountSessions: prepareQuery('SELECT * FROM sessions WHERE account_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT ?'),
		findSessionById: prepareQuery('SELECT * FROM sessions WHERE session_id = ? AND account_id = ? AND expires_at > ?'),
		deleteSessionById: prepareQuery('DELETE FROM sessions WHERE session_id = ? AND account_id = ?'),
		deleteAccountSessions: prepareQuery('DELETE FROM sessions WHERE account_id = ?'),
		deleteExpiredSessions: prepareQuery('DELETE FROM sessions WHERE expires_at <= ?'),
		findRateLimit: prepareQuery('SELECT * FROM rate_limits WHERE bucket_hash = ?'),
		resetRateLimit: prepareQuery(`
			INSERT INTO rate_limits (bucket_hash, window_started_at, attempts, expires_at)
			VALUES (?, ?, 1, ?)
			ON CONFLICT(bucket_hash) DO UPDATE SET
				window_started_at = excluded.window_started_at,
				attempts = 1,
				expires_at = excluded.expires_at
		`),
		incrementRateLimit: prepareQuery('UPDATE rate_limits SET attempts = attempts + 1 WHERE bucket_hash = ?'),
		deleteExpiredRateLimits: prepareQuery('DELETE FROM rate_limits WHERE expires_at <= ?'),
		insertAuditEvent: prepareQuery(`
			INSERT INTO audit_events (
				actor_account_id, actor_email, action, affected_account_id,
				affected_email, occurred_at, metadata_json
			) VALUES (?, ?, ?, ?, ?, ?, ?)
		`),
		countAuditEvents: prepareQuery(`SELECT COUNT(*) AS count FROM audit_events WHERE ${auditSearch}`),
		listAuditEvents: prepareQuery(`
			SELECT * FROM audit_events WHERE ${auditSearch}
			ORDER BY occurred_at DESC, event_id DESC LIMIT ? OFFSET ?
		`),
		listAccountAuditEvents: prepareQuery(`
			SELECT * FROM audit_events
			WHERE affected_account_id = ? OR actor_account_id = ?
			ORDER BY occurred_at DESC, event_id DESC LIMIT ?
		`),
		findToken: prepareQuery('SELECT * FROM account_tokens WHERE token_hash = ?'),
		insertAccountToken: prepareQuery(`
			INSERT INTO account_tokens (token_hash, account_id, purpose, email, expires_at, used_at)
			VALUES (?, ?, ?, ?, ?, NULL)
		`),
		deleteAccountTokensByPurpose: prepareQuery('DELETE FROM account_tokens WHERE account_id = ? AND purpose = ? AND used_at IS NULL'),
		markTokenUsed: prepareQuery('UPDATE account_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL'),
		invalidateAccountTokens: prepareQuery('DELETE FROM account_tokens WHERE account_id = ? AND used_at IS NULL'),
		countAccounts: prepareQuery(`
			SELECT COUNT(*) AS count FROM accounts
			WHERE ${accountSearch} AND (? = 'all' OR status = ?)
		`),
		listAccounts: prepareQuery(`
			SELECT * FROM accounts
			WHERE ${accountSearch} AND (? = 'all' OR status = ?)
			ORDER BY created_at DESC, id LIMIT ? OFFSET ?
		`)
	};
}

async function withTransaction(callback) {
	if (postgresPool) {
		const client = await postgresPool.connect();
		try {
			await client.query('BEGIN');
			return await transactionStorage.run(client, async () => {
				const result = await callback();
				await client.query('COMMIT');
				return result;
			});
		} catch (error) {
			await client.query('ROLLBACK');
			throw error;
		} finally {
			client.release();
		}
	}

	database.exec('BEGIN IMMEDIATE');
	try {
		const result = await callback();
		database.exec('COMMIT');
		return result;
	} catch (error) {
		database.exec('ROLLBACK');
		throw error;
	}
}

function sendJson(response, status, value, headers = {}) {
	response.writeHead(status, {
		'Content-Type': 'application/json; charset=utf-8',
		'Cache-Control': 'no-store',
		...headers
	});
	response.end(JSON.stringify(value));
}

function createError(status, message, retryAfterSeconds) {
	const error = new Error(message);
	error.status = status;
	if (retryAfterSeconds) error.retryAfterSeconds = retryAfterSeconds;
	return error;
}

function isUniqueConstraintError(error) {
	return error?.code === '23505' || error?.message?.includes('UNIQUE constraint failed');
}

function positiveIntegerSetting(name, fallback) {
	const value = Number(process.env[name]);
	return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function usePostgresBackend() {
	if (process.env.DB_BACKEND === 'sqlite') return false;
	return process.env.DB_BACKEND === 'postgres' || Boolean(process.env.DATABASE_URL);
}

async function readBody(request) {
	const chunks = [];
	let size = 0;

	for await (const chunk of request) {
		size += chunk.length;
		if (size > maxBodySize) throw createError(413, 'Request is too large.');
		chunks.push(chunk);
	}

	let body;
	try {
		body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
	} catch {
		throw createError(400, 'Please send valid JSON.');
	}
	if (!body || typeof body !== 'object' || Array.isArray(body)) {
		throw createError(400, 'Please send a JSON object.');
	}
	return body;
}

function normalizeEmail(email) {
	return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function publicAccount(account) {
	return {
		id: account.id,
		email: account.email,
		displayName: account.displayName,
		createdAt: account.createdAt,
		role: account.role,
		status: account.status,
		emailVerified: Boolean(account.emailVerifiedAt),
		pendingEmail: account.pendingEmail || null
	};
}

const appHealthState = { recentEmailFailures: 0, lastHealthCheckAt: null };

async function checkDatabaseHealth() {
	const backend = usePostgresBackend() ? 'postgres' : 'sqlite';
	const checkedAt = new Date().toISOString();
	try {
		if (backend === 'postgres') {
			await postgresPool.query('SELECT 1');
		} else {
			const probe = new DatabaseSync(databaseFile, { readOnly: true });
			try {
				const result = probe.prepare('PRAGMA integrity_check').get();
				if (result.integrity_check !== 'ok') throw new Error('SQLite integrity check failed.');
				await queries.count.get();
			} finally {
				probe.close();
			}
		}
		return {
			backend,
			status: 'healthy',
			checkedAt,
			summary: backend === 'postgres'
				? 'The database is reachable and responding to health checks.'
				: 'The SQLite database passed integrity checks and is readable.'
		};
	} catch (error) {
		return {
			backend,
			status: 'unavailable',
			checkedAt,
			summary: 'The database is currently unavailable or failed its integrity check.'
		};
	}
}

function checkEmailHealth() {
	const configured = Boolean(process.env.SMTP_HOST && process.env.MAIL_FROM);
	let status = configured ? 'healthy' : 'degraded';
	if (!configured && process.env.NODE_ENV === 'production') status = 'unavailable';
	if (appHealthState.recentEmailFailures > 0) status = 'degraded';
	return {
		configured,
		status,
		recentDeliveryFailures: appHealthState.recentEmailFailures,
		summary: configured
			? (appHealthState.recentEmailFailures > 0 ? 'Email delivery is configured, but recent sends have failed.' : 'Email delivery is configured and ready to send account notifications.')
			: 'Email delivery is not configured, so account notifications may fail.'
	};
}

async function checkBackupHealth() {
	const backend = usePostgresBackend() ? 'postgres' : 'sqlite';
	if (backend === 'postgres') {
		return {
			backend,
			status: 'healthy',
			summary: 'Backup and recovery are managed by the database platform and are not exposed here.'
		};
	}
	try {
		await fs.access(databaseFile);
		return {
			backend,
			status: 'healthy',
			summary: 'SQLite data is present; use the backup tooling to create a verified copy.'
		};
	} catch {
		return {
			backend,
			status: 'degraded',
			summary: 'The SQLite database file is not available, so backup verification may be incomplete.'
		};
	}
}

async function getOperationalStatus() {
	const database = await checkDatabaseHealth();
	const email = checkEmailHealth();
	const backup = await checkBackupHealth();
	appHealthState.lastHealthCheckAt = new Date().toISOString();
	const overall = [database.status, email.status, backup.status].some(status => status === 'unavailable')
		? 'unavailable'
		: ([database.status, email.status, backup.status].some(status => status === 'degraded') ? 'degraded' : 'healthy');
	return {
		checkedAt: appHealthState.lastHealthCheckAt,
		overall,
		database,
		email,
		backup
	};
}

function accountFromRow(row) {
	if (!row) return null;
	return {
		id: row.id,
		email: row.email,
		displayName: row.display_name,
		createdAt: row.created_at,
		role: row.role,
		status: row.status,
		emailVerifiedAt: row.email_verified_at,
		pendingEmail: row.pending_email,
		pendingEmail: row.pending_email,
		salt: row.salt,
		passwordHash: row.password_hash
	};
}

function isSecureRequest(request) {
	if (request.socket.encrypted) return true;
	const forwardedProtocol = request.headers['x-forwarded-proto']?.split(',')[0].trim().toLowerCase();
	return process.env.TRUST_PROXY === 'true' && forwardedProtocol === 'https';
}

function sessionCookie(value, maxAge, secure = false) {
	const secureAttribute = secure ? '; Secure' : '';
	return `session=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secureAttribute}`;
}

function clearSessionCookie(request) {
	return sessionCookie('', 0, isSecureRequest(request));
}

async function getAccountForRequest(request) {
	const cookie = request.headers.cookie || '';
	const token = cookie.match(/(?:^|;\s*)session=([a-f0-9]+)/)?.[1];
	if (!token) return null;

	const tokenHash = hashToken(token);
	const session = await queries.findSessionByToken.get(tokenHash);
	if (!session || session.expires_at <= Date.now()) {
		if (session) await queries.deleteSessionByToken.run(tokenHash);
		return null;
	}

	const account = accountFromRow(await queries.findById.get(session.account_id));
 	return account?.status === 'active' ? account : null;
}

function getSessionToken(request) {
	return (request.headers.cookie || '').match(/(?:^|;\s*)session=([a-f0-9]+)/)?.[1] || null;
}

async function issueSession(accountId, userAgent = '') {
	const token = randomBytes(32).toString('hex');
	const now = Date.now();
	await queries.insertSession.run(randomBytes(16).toString('hex'), hashToken(token), accountId, now, now + sessionLifetime, userAgent.slice(0, 300));
	return token;
}

async function sessionCookieForRequest(request, accountId) {
	return sessionCookie(
		await issueSession(accountId, request.headers['user-agent'] || ''),
		Math.floor(sessionLifetime / 1000),
		isSecureRequest(request)
	);
}

async function consumeRateLimit(request, scope, identifier, limit) {
	const forwardedAddress = process.env.TRUST_PROXY === 'true'
		? request.headers['x-forwarded-for']?.split(',')[0].trim()
		: undefined;
	const address = forwardedAddress || request.socket.remoteAddress || 'unknown';
	const rawBucket = identifier === undefined ? `ip:${address}` : `identifier:${identifier}`;
	const bucketHash = hashToken(`${scope}\0${rawBucket}`);
	const now = Date.now();
	let retryAfterSeconds = 0;

	await withTransaction(async () => {
		const bucket = await queries.findRateLimit.get(bucketHash);
		if (!bucket || bucket.expires_at <= now) {
			await queries.resetRateLimit.run(bucketHash, now, now + rateLimitWindowMs);
		} else if (bucket.attempts >= limit) {
			retryAfterSeconds = Math.max(1, Math.ceil((bucket.expires_at - now) / 1000));
		} else {
			await queries.incrementRateLimit.run(bucketHash);
		}
		await queries.deleteExpiredRateLimits.run(now);
	});

	if (retryAfterSeconds) {
		throw createError(429, 'Too many requests. Please try again later.', retryAfterSeconds);
	}
}

async function recordAuditEvent(actor, action, affectedAccount = actor, metadata = {}) {
	await queries.insertAuditEvent.run(
		actor?.id || null,
		actor?.email || null,
		action,
		affectedAccount?.id || null,
		affectedAccount?.email || null,
		new Date().toISOString(),
		JSON.stringify(metadata)
	);
}

async function hashPassword(password, salt = randomBytes(16).toString('hex')) {
	const hash = await scrypt(password, salt, passwordLength);
	return { salt, passwordHash: hash.toString('hex') };
}

async function passwordMatches(password, account) {
	const candidate = await scrypt(password, account.salt, passwordLength);
	const expected = Buffer.from(account.passwordHash, 'hex');
	return expected.length === candidate.length && timingSafeEqual(candidate, expected);
}

function validateEmail(email) {
	return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
	return typeof password === 'string' && password.length >= 10 && password.length <= 200;
}

function hashToken(token) {
	return createHash('sha256').update(token).digest('hex');
}

function base32Encode(buffer) {
	const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	let bits = 0;
	let value = 0;
	let output = '';
	for (const byte of buffer) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			output += alphabet[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0) {
		output += alphabet[(value << (5 - bits)) & 31];
	}
	return output;
}

function base32Decode(secret) {
	const normalized = secret.replace(/\s+/g, '').toUpperCase();
	let bits = '';
	for (const character of normalized) {
		const index = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(character);
		if (index === -1) throw new Error('Invalid MFA secret.');
		bits += index.toString(2).padStart(5, '0');
	}
	const chunks = [];
	for (let index = 0; index + 8 <= bits.length; index += 8) {
		chunks.push(parseInt(bits.slice(index, index + 8), 2));
	}
	return Buffer.from(chunks);
}

function generateTotpSecret() {
	return base32Encode(randomBytes(20));
}

function totpCode(secret, time = Date.now()) {
	const key = base32Decode(secret);
	const counter = Math.floor(time / 30000);
	const buffer = Buffer.alloc(8);
	let value = counter;
	for (let index = 7; index >= 0; index -= 1) {
		buffer[index] = value & 0xff;
		value = Math.floor(value / 256);
	}
	const digest = createHmac('sha1', key).update(buffer).digest();
	const offset = digest[digest.length - 1] & 0x0f;
	const binary = ((digest[offset] & 0x7f) << 24)
		| ((digest[offset + 1] & 0xff) << 16)
		| ((digest[offset + 2] & 0xff) << 8)
		| (digest[offset + 3] & 0xff);
	return String(binary % 1000000).padStart(6, '0');
}

function verifyTotpCode(secret, code) {
	if (typeof code !== 'string') return false;
	const trimmedCode = code.trim();
	if (!/^\d{6}$/.test(trimmedCode)) return false;
	const window = [0, -1, 1];
	for (const offset of window) {
		if (totpCode(secret, Date.now() + offset * 30000) === trimmedCode) return true;
	}
	return false;
}

function totpOtpauthUri(email, secret) {
	const label = encodeURIComponent(`Account Desk:${email}`);
	return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent('Account Desk')}`;
}

async function createAccountToken(accountId, purpose, email, lifetime) {
	const token = randomBytes(32).toString('base64url');
	const now = Date.now();
	await queries.deleteAccountTokensByPurpose.run(accountId, purpose);
	await queries.insertAccountToken.run(hashToken(token), accountId, purpose, email, now + lifetime);
	return token;
}

function accountActionUrl(purpose, token) {
	const baseUrl = process.env.APP_BASE_URL || `http://localhost:${Number(process.env.PORT) || 3000}`;
	const url = new URL('/', baseUrl);
	if (purpose === 'verify_email') url.searchParams.set('verify', token);
	else if (purpose === 'password_reset') url.searchParams.set('reset', token);
	else if (purpose === 'invite') url.searchParams.set('invite', token);
	return url.toString();
}

async function sendAccountEmail(purpose, email, token) {
	const url = accountActionUrl(purpose, token);
	const verification = purpose === 'verify_email';
	const reset = purpose === 'password_reset';
	const invite = purpose === 'invite';
	const subject = verification ? 'Verify your email address' : reset ? 'Reset your password' : 'You are invited to Account Desk';
	const action = verification ? 'Verify your email address' : reset ? 'Choose a new password' : 'Create your account';
	const lifetimeText = verification ? '24 hours' : reset ? '15 minutes' : '3 days';
	const text = `${action}: ${url}\n\nThis link expires in ${lifetimeText} and can only be used once.`;

	if (process.env.SMTP_HOST) {
		if (!process.env.MAIL_FROM) throw createError(503, 'Set MAIL_FROM to configure email delivery.');
		if (!mailTransport) {
			const port = Number(process.env.SMTP_PORT) || 587;
			const auth = process.env.SMTP_USER
				? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' }
				: undefined;
			mailTransport = nodemailer.createTransport({
				host: process.env.SMTP_HOST,
				port,
				secure: process.env.SMTP_SECURE === 'true' || port === 465,
				auth
			});
		}
		try {
			await mailTransport.sendMail({ from: process.env.MAIL_FROM, to: email, subject, text });
			appHealthState.recentEmailFailures = 0;
			return;
		} catch (error) {
			appHealthState.recentEmailFailures += 1;
			console.error('Account email delivery failed:', {
				code: error.code,
				responseCode: error.responseCode,
				command: error.command
			});
			throw createError(503, 'Email delivery failed. Check the SMTP settings and try again.');
		}
	}

	if (process.env.NODE_ENV === 'production') {
		throw createError(503, 'Email delivery is not configured. Set SMTP_HOST and MAIL_FROM.');
	}
	console.log(`[DEV EMAIL ${purpose}] ${email} ${url}`);
}

async function readRedeemableToken(token, purpose) {
	if (typeof token !== 'string' || token.length > 128) throw createError(400, 'This link is invalid.');
	const record = await queries.findToken.get(hashToken(token));
	if (!record || record.purpose !== purpose) throw createError(400, 'This link is invalid.');
	if (record.used_at !== null) throw createError(409, 'This link has already been used.');
	if (record.expires_at <= Date.now()) throw createError(410, 'This link has expired.');
	return record;
}

async function verifyEmailToken(token) {
	return withTransaction(async () => {
		const record = await readRedeemableToken(token, 'verify_email');
		const account = accountFromRow(await queries.findById.get(record.account_id));
		if (!account || (account.email !== record.email && account.pendingEmail !== record.email)) {
			throw createError(400, 'This verification link is invalid.');
		}
		if (account.pendingEmail === record.email) {
			const owner = await queries.findEmailOwner.get(record.email, record.email, account.id);
			if (owner) throw createError(409, 'That email address is already associated with another account.');
		}
		await queries.verifyEmail.run(record.email, new Date().toISOString(), account.id);
		await queries.markTokenUsed.run(Date.now(), record.token_hash);
		return account;
	});
}

async function resetPasswordWithToken(token, password) {
	if (!validatePassword(password)) throw createError(400, 'Password must be between 10 and 200 characters.');
	const initialRecord = await readRedeemableToken(token, 'password_reset');
	const account = accountFromRow(await queries.findById.get(initialRecord.account_id));
	if (!account || account.status !== 'active') throw createError(400, 'This link is invalid.');
	const credentials = await hashPassword(password);

	await withTransaction(async () => {
		const record = await readRedeemableToken(token, 'password_reset');
		if (record.account_id !== account.id) throw createError(400, 'This link is invalid.');
		await queries.updatePassword.run(credentials.salt, credentials.passwordHash, account.id);
		await queries.markTokenUsed.run(Date.now(), record.token_hash);
		await queries.deleteAccountSessions.run(account.id);
		await recordAuditEvent(account, 'password.reset');
	});
}

async function handleApi(request, response, url) {
	if (url.pathname.startsWith('/api/admin/audit-events')) {
		const administrator = await getAccountForRequest(request);
		if (!administrator) throw createError(401, 'Please sign in to continue.');
		if (administrator.role !== 'admin') throw createError(403, 'Administrator access is required.');
		if (request.method !== 'GET' || url.pathname !== '/api/admin/audit-events') {
			throw createError(404, 'That audit endpoint does not exist.');
		}

		const search = (url.searchParams.get('q') || '').trim().slice(0, 100);
		const action = (url.searchParams.get('action') || '').trim().slice(0, 80);
		const actorEmail = (url.searchParams.get('actorEmail') || '').trim().slice(0, 254);
		const affectedEmail = (url.searchParams.get('affectedEmail') || '').trim().slice(0, 254);
		const from = (url.searchParams.get('from') || '').trim();
		const to = (url.searchParams.get('to') || '').trim();
		const format = url.searchParams.get('format') === 'csv' ? 'csv' : 'json';
		const requestedLimit = Number(url.searchParams.get('limit')) || 20;
		const requestedOffset = Number(url.searchParams.get('offset')) || 0;
		const limit = Math.min(100, Math.max(1, Math.floor(requestedLimit)));
		const offset = Math.min(1000000, Math.max(0, Math.floor(requestedOffset)));
		const filters = [search, search, search, search, search, search];
		const baseEvents = (await queries.listAuditEvents.all(...filters, 10000, 0)).map(event => ({
			id: event.event_id,
			actorAccountId: event.actor_account_id,
			actorEmail: event.actor_email,
			action: event.action,
			affectedAccountId: event.affected_account_id,
			affectedEmail: event.affected_email,
			occurredAt: event.occurred_at,
			metadata: JSON.parse(event.metadata_json)
		}));
		const filteredEvents = baseEvents.filter(event => {
			if (action && !event.action.toLowerCase().includes(action.toLowerCase())) return false;
			if (actorEmail && !(event.actorEmail || '').toLowerCase().includes(actorEmail.toLowerCase())) return false;
			if (affectedEmail && !(event.affectedEmail || '').toLowerCase().includes(affectedEmail.toLowerCase())) return false;
			if (from && event.occurredAt < from) return false;
			if (to && event.occurredAt > to) return false;
			return true;
		});
		const total = filteredEvents.length;
		const events = filteredEvents.slice(offset, offset + limit);
		if (format === 'csv') {
			const header = ['event_id', 'actor_account_id', 'actor_email', 'action', 'affected_account_id', 'affected_email', 'occurred_at', 'metadata_json'];
			const csvRows = [header];
			for (const event of filteredEvents) {
				csvRows.push([
					event.id,
					event.actorAccountId ?? '',
					event.actorEmail ?? '',
					event.action,
					event.affectedAccountId ?? '',
					event.affectedEmail ?? '',
					event.occurredAt,
					JSON.stringify(event.metadata ?? {})
				]);
			}
			const escapeCsv = value => `"${String(value ?? '').replace(/"/g, '""').replace(/\r?\n/g, ' ')}"`;
			const csv = csvRows.map(row => row.map(escapeCsv).join(',')).join('\n');
			response.writeHead(200, {
				'Content-Type': 'text/csv; charset=utf-8',
				'Content-Disposition': 'attachment; filename="audit-events.csv"',
				'Cache-Control': 'no-store'
			});
			response.end(csv);
			return;
		}
		return sendJson(response, 200, { events, total, limit, offset });
	}

	if (request.method === 'POST' && url.pathname === '/api/email/verify') {
		const body = await readBody(request);
		const account = await verifyEmailToken(body.token);
		return sendJson(response, 200, { verified: true, account: publicAccount(accountFromRow(await queries.findById.get(account.id))) });
	}

	if (request.method === 'POST' && url.pathname === '/api/password-reset/request') {
		await consumeRateLimit(request, 'password-reset:ip', undefined, positiveIntegerSetting('RATE_LIMIT_PASSWORD_RESET_IP_MAX', 10));
		const body = await readBody(request);
		const email = normalizeEmail(body.email);
		if (validateEmail(email)) {
			await consumeRateLimit(request, 'password-reset:email', email, positiveIntegerSetting('RATE_LIMIT_PASSWORD_RESET_EMAIL_MAX', 4));
		}
		const account = accountFromRow(await queries.findByEmail.get(email));
		if (account && account.status === 'active' && account.emailVerifiedAt) {
			const token = await createAccountToken(account.id, 'password_reset', account.email, resetLifetime);
			try {
				await sendAccountEmail('password_reset', account.email, token);
			} catch (error) {
				console.error('Password reset email delivery failed:', {
					code: error.code,
					responseCode: error.responseCode,
					command: error.command
				});
			}
		}
		return sendJson(response, 200, { message: 'If that verified email belongs to an account, a reset link has been sent.' });
	}

	if (request.method === 'POST' && url.pathname === '/api/password-reset/complete') {
		const body = await readBody(request);
		await resetPasswordWithToken(body.token, body.password);
		return sendJson(response, 200, { message: 'Your password has been reset. Sign in with your new password.' });
	}

	if (request.method === 'POST' && url.pathname === '/api/invitation/accept') {
		const body = await readBody(request);
		const token = typeof body.token === 'string' ? body.token : '';
		const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
		if (!displayName || displayName.length > 80) throw createError(400, 'Enter a name of 1 to 80 characters.');
		if (!validatePassword(body.password)) throw createError(400, 'Password must be between 10 and 200 characters.');

		const account = await withTransaction(async () => {
			const record = await readRedeemableToken(token, 'invite');
			const email = normalizeEmail(record.email);
			if (!validateEmail(email)) throw createError(400, 'This invitation is invalid.');
			if (await queries.findByEmail.get(email)) {
				throw createError(409, 'An account already uses that email address.');
			}
			const credentials = await hashPassword(body.password);
			const id = randomBytes(16).toString('hex');
			await queries.insert.run(id, email, displayName, new Date().toISOString(), 'user', 'active', credentials.salt, credentials.passwordHash);
			await queries.verifyEmail.run(email, new Date().toISOString(), id);
			await queries.markTokenUsed.run(Date.now(), record.token_hash);
			await recordAuditEvent({ id: record.account_id }, 'invitation.accepted', { id, email }, { invitedBy: record.account_id, invitedEmail: email });
			return accountFromRow(await queries.findById.get(id));
		});

		return sendJson(response, 201, { account: publicAccount(account) }, {
			'Set-Cookie': await sessionCookieForRequest(request, account.id)
		});
	}

	if (request.method === 'GET' && url.pathname === '/api/admin/status') {
		const administrator = await getAccountForRequest(request);
		if (!administrator) throw createError(401, 'Please sign in to continue.');
		if (administrator.role !== 'admin') throw createError(403, 'Administrator access is required.');
		return sendJson(response, 200, await getOperationalStatus());
	}

	if (url.pathname === '/api/admin/invitations') {
		const administrator = await getAccountForRequest(request);
		if (!administrator) throw createError(401, 'Please sign in to continue.');
		if (administrator.role !== 'admin') throw createError(403, 'Administrator access is required.');

		if (request.method === 'POST') {
			const body = await readBody(request);
			const email = normalizeEmail(body.email);
			if (!validateEmail(email)) throw createError(400, 'Enter a valid email address.');
			const existingAccount = await queries.findByEmail.get(email);
			const activeInvitation = await queries.findActiveInvitationByEmail.get('invite', email, Date.now());
			if (existingAccount || activeInvitation) {
				return sendJson(response, 200, { message: 'If that address is available, an invitation has been sent.' });
			}
			const token = await createAccountToken(administrator.id, 'invite', email, inviteLifetime);
			await sendAccountEmail('invite', email, token);
			await recordAuditEvent(administrator, 'invitation.created', administrator, { email });
			return sendJson(response, 200, { message: 'An invitation has been sent.' });
		}

		if (request.method === 'DELETE') {
			const body = await readBody(request);
			const email = normalizeEmail(body.email);
			if (!validateEmail(email)) throw createError(400, 'Enter a valid email address.');
			const deleted = await queries.deleteInvitationByEmail.run(Date.now(), email);
			if (deleted.rowCount && deleted.rowCount > 0) {
				await recordAuditEvent(administrator, 'invitation.cancelled', administrator, { email });
			}
			return sendJson(response, 200, { message: 'Invitation cancelled.' });
		}

		throw createError(404, 'That admin endpoint does not exist.');
	}

	if (url.pathname.startsWith('/api/admin/accounts')) {
		const administrator = await getAccountForRequest(request);
		if (!administrator) throw createError(401, 'Please sign in to continue.');
		if (administrator.role !== 'admin') throw createError(403, 'Administrator access is required.');

		if (request.method === 'GET' && url.pathname === '/api/admin/accounts') {
			const search = (url.searchParams.get('q') || '').trim().slice(0, 100);
			const requestedLimit = Number(url.searchParams.get('limit')) || 10;
			const requestedOffset = Number(url.searchParams.get('offset')) || 0;
			const limit = Math.min(50, Math.max(1, Math.floor(requestedLimit)));
			const offset = Math.min(1000000, Math.max(0, Math.floor(requestedOffset)));
			const status = ['active', 'suspended'].includes(url.searchParams.get('status'))
				? url.searchParams.get('status')
				: 'all';
			const filters = [search, search, search, status, status];
			const total = (await queries.countAccounts.get(...filters)).count;
			const accountList = (await queries.listAccounts.all(...filters, limit, offset))
				.map(row => publicAccount(accountFromRow(row)));
			return sendJson(response, 200, { accounts: accountList, total, limit, offset });
		}

		const accountMatch = url.pathname.match(/^\/api\/admin\/accounts\/([a-f0-9]+)$/);
		if (request.method === 'GET' && accountMatch) {
			const target = accountFromRow(await queries.findById.get(accountMatch[1]));
			if (!target) throw createError(404, 'Account not found.');

			const [activeSessions, recentAudit] = await Promise.all([
				queries.listAccountSessions.all(target.id, Date.now(), 5),
				queries.listAccountAuditEvents.all(target.id, target.id, 10)
			]);

			return sendJson(response, 200, {
				account: publicAccount(target),
				recentSessions: activeSessions.map(session => ({
					id: session.session_id,
					userAgent: session.user_agent,
					createdAt: session.created_at,
					expiresAt: session.expires_at
				})),
				recentAudit: recentAudit.map(event => {
					let metadata = {};
					try {
						metadata = JSON.parse(event.metadata_json || '{}');
					} catch {
						metadata = {};
					}
					return {
						id: event.event_id,
						actorAccountId: event.actor_account_id,
						actorEmail: event.actor_email,
						action: event.action,
						affectedAccountId: event.affected_account_id,
						affectedEmail: event.affected_email,
						occurredAt: event.occurred_at,
						metadata
					};
				})
			});
		}

		const roleMatch = url.pathname.match(/^\/api\/admin\/accounts\/([a-f0-9]+)\/role$/);
		if (request.method === 'PATCH' && roleMatch) {
			const body = await readBody(request);
			if (!['user', 'admin'].includes(body.role)) throw createError(400, 'Role must be user or admin.');
			const target = accountFromRow(await queries.findById.get(roleMatch[1]));
			if (!target) throw createError(404, 'Account not found.');

			await withTransaction(async () => {
				if (target.role === 'admin' && body.role === 'user' && (await queries.adminCount.get()).count <= 1) {
					throw createError(409, 'The last administrator cannot be demoted.');
				}
				if (target.role !== body.role) {
					await queries.updateRole.run(body.role, target.id);
					await recordAuditEvent(administrator, 'role.changed', target, { from: target.role, to: body.role });
				}
			});
			return sendJson(response, 200, { account: { ...publicAccount(target), role: body.role } });
		}

		const statusMatch = url.pathname.match(/^\/api\/admin\/accounts\/([a-f0-9]+)\/status$/);
		if (request.method === 'PATCH' && statusMatch) {
			const body = await readBody(request);
			if (!['active', 'suspended'].includes(body.status)) {
				throw createError(400, 'Status must be active or suspended.');
			}
			const target = accountFromRow(await queries.findById.get(statusMatch[1]));
			if (!target) throw createError(404, 'Account not found.');
			if (target.id === administrator.id && body.status === 'suspended') {
				throw createError(409, 'You cannot suspend your own administrator account.');
			}

			await withTransaction(async () => {
				if (target.role === 'admin' && body.status === 'suspended' && (await queries.activeAdminCount.get()).count <= 1) {
					throw createError(409, 'The last active administrator cannot be suspended.');
				}
				if (target.status !== body.status) {
					await queries.updateStatus.run(body.status, target.id);
					if (body.status === 'suspended') await queries.deleteAccountSessions.run(target.id);
					const action = body.status === 'suspended' ? 'account.suspended' : 'account.reactivated';
					await recordAuditEvent(administrator, action, target, { from: target.status, to: body.status });
				}
			});
			return sendJson(response, 200, { account: { ...publicAccount(target), status: body.status } });
		}

		throw createError(404, 'That admin endpoint does not exist.');
	}

	if (request.method === 'POST' && url.pathname === '/api/register') {
		await consumeRateLimit(request, 'registration:ip', undefined, positiveIntegerSetting('RATE_LIMIT_REGISTRATION_IP_MAX', 15));
		const body = await readBody(request);
		const email = normalizeEmail(body.email);
		const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';

		if (!displayName || displayName.length > 80) throw createError(400, 'Enter a name of 1 to 80 characters.');
		if (!validateEmail(email)) throw createError(400, 'Enter a valid email address.');
		if (!validatePassword(body.password)) throw createError(400, 'Password must be between 10 and 200 characters.');
		await consumeRateLimit(request, 'registration:email', email, positiveIntegerSetting('RATE_LIMIT_REGISTRATION_EMAIL_MAX', 3));
		if (await queries.findByEmail.get(email)) {
			throw createError(409, 'An account already uses that email address.');
		}

		const credentials = await hashPassword(body.password);
		const account = {
			id: randomBytes(16).toString('hex'),
			email,
			displayName,
			createdAt: new Date().toISOString(),
			role: 'user',
			status: 'active',
			...credentials
		};
		try {
			await queries.insert.run(account.id, account.email, account.displayName, account.createdAt, account.role, account.status, account.salt, account.passwordHash);
		} catch (error) {
			if (isUniqueConstraintError(error)) {
				throw createError(409, 'An account already uses that email address.');
			}
			throw error;
		}
		const verificationToken = await createAccountToken(account.id, 'verify_email', account.email, verificationLifetime);
		await sendAccountEmail('verify_email', account.email, verificationToken);
		return sendJson(response, 201, { account: publicAccount(account) }, {
			'Set-Cookie': await sessionCookieForRequest(request, account.id)
		});
	}

	if (request.method === 'POST' && url.pathname === '/api/login') {
		await consumeRateLimit(request, 'sign-in:ip', undefined, positiveIntegerSetting('RATE_LIMIT_SIGN_IN_IP_MAX', 20));
		const body = await readBody(request);
		const email = normalizeEmail(body.email);
		if (validateEmail(email)) {
			await consumeRateLimit(request, 'sign-in:email', email, positiveIntegerSetting('RATE_LIMIT_SIGN_IN_EMAIL_MAX', 8));
		}
		const account = accountFromRow(await queries.findByEmail.get(email));
		const password = typeof body.password === 'string' ? body.password : '';
		const validPassword = await passwordMatches(password, account || dummyPasswordCredentials);
		if (!account || !validPassword || account.status !== 'active') {
			throw createError(401, 'Email or password is incorrect.');
		}

		if (account.role === 'admin') {
			const mfaSecret = await queries.findMfaSecret.get(account.id);
			if (mfaSecret && mfaSecret.enabled) {
				if (typeof body.code !== 'string') throw createError(401, 'Multi-factor authentication code is required.');
				if (!verifyTotpCode(mfaSecret.secret, body.code)) throw createError(401, 'Invalid or expired multi-factor authentication code.');
			}
		}
		await recordAuditEvent(account, 'sign_in.succeeded');
		return sendJson(response, 200, { account: publicAccount(account) }, {
			'Set-Cookie': await sessionCookieForRequest(request, account.id)
		});
	}

	if (request.method === 'POST' && url.pathname === '/api/logout') {
		const token = getSessionToken(request);
		if (token) await queries.deleteSessionByToken.run(hashToken(token));
		return sendJson(response, 200, { ok: true }, { 'Set-Cookie': clearSessionCookie(request) });
	}

	const account = await getAccountForRequest(request);
	if (!account) throw createError(401, 'Please sign in to continue.');

	if (request.method === 'GET' && url.pathname === '/api/me') {
		return sendJson(response, 200, { account: publicAccount(account) });
	}

	if (request.method === 'GET' && url.pathname === '/api/me/sessions') {
		const currentToken = getSessionToken(request);
		const currentHash = currentToken ? hashToken(currentToken) : null;
		const activeSessions = (await queries.listSessions.all(account.id, Date.now())).map(session => ({
			id: session.session_id,
			createdAt: new Date(session.created_at).toISOString(),
			expiresAt: new Date(session.expires_at).toISOString(),
			userAgent: session.user_agent || 'Unknown device',
			current: session.token_hash === currentHash
		}));
		return sendJson(response, 200, { sessions: activeSessions });
	}

	const sessionMatch = url.pathname.match(/^\/api\/me\/sessions\/([a-f0-9]+)$/);
	if (request.method === 'DELETE' && sessionMatch) {
		const session = await queries.findSessionById.get(sessionMatch[1], account.id, Date.now());
		if (!session) throw createError(404, 'Active session not found.');
		const current = session.token_hash === hashToken(getSessionToken(request) || '');
		await queries.deleteSessionById.run(session.session_id, account.id);
		return sendJson(response, 200, { revoked: true, current }, current
			? { 'Set-Cookie': clearSessionCookie(request) }
			: {});
	}

	if (request.method === 'PATCH' && url.pathname === '/api/me') {
		const body = await readBody(request);
		const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
		const email = normalizeEmail(body.email);

		if (!displayName || displayName.length > 80) throw createError(400, 'Enter a name of 1 to 80 characters.');
		if (!validateEmail(email)) throw createError(400, 'Enter a valid email address.');
		const changingEmail = email !== account.email && email !== account.pendingEmail;
		if (changingEmail) {
			if (await queries.findEmailOwner.get(email, email, account.id)) {
				throw createError(409, 'An account already uses that email address.');
			}
		}
		const changedFields = [];
		if (displayName !== account.displayName) changedFields.push('displayName');
		if (changingEmail) changedFields.push('email');
		await withTransaction(async () => {
			await queries.update.run(displayName, account.id);
			if (changingEmail) await queries.updatePendingEmail.run(email, account.id);
			if (changedFields.length > 0) {
				await recordAuditEvent(account, 'profile.updated', account, { changedFields });
			}
		}).catch(error => {
			if (isUniqueConstraintError(error)) {
				throw createError(409, 'An account already uses that email address.');
			}
			throw error;
		});
		account.displayName = displayName;
		if (changingEmail) {
			account.pendingEmail = email;
			const verificationToken = await createAccountToken(account.id, 'verify_email', email, verificationLifetime);
			await sendAccountEmail('verify_email', email, verificationToken);
		}
		return sendJson(response, 200, { account: publicAccount(account) });
	}

	if (request.method === 'POST' && url.pathname === '/api/me/verification-email') {
		if (account.emailVerifiedAt && !account.pendingEmail) {
			throw createError(409, 'Your current email address is already verified.');
		}
		const email = account.pendingEmail || account.email;
		const token = await createAccountToken(account.id, 'verify_email', email, verificationLifetime);
		await sendAccountEmail('verify_email', email, token);
		return sendJson(response, 200, { message: `A verification link has been sent to ${email}.` });
	}

	if (request.method === 'POST' && url.pathname === '/api/me/password') {
		const body = await readBody(request);
		if (typeof body.currentPassword !== 'string' || !(await passwordMatches(body.currentPassword, account))) {
			throw createError(401, 'Your current password is incorrect.');
		}
		if (!validatePassword(body.newPassword)) {
			throw createError(400, 'New password must be between 10 and 200 characters.');
		}
		if (body.currentPassword === body.newPassword) {
			throw createError(400, 'Choose a new password different from your current password.');
		}

		const credentials = await hashPassword(body.newPassword);
		await withTransaction(async () => {
			await queries.updatePassword.run(credentials.salt, credentials.passwordHash, account.id);
			await queries.invalidateAccountTokens.run(account.id);
			await queries.deleteAccountSessions.run(account.id);
			await recordAuditEvent(account, 'password.changed');
		});
		return sendJson(response, 200, { message: 'Password changed successfully.' }, {
			'Set-Cookie': await sessionCookieForRequest(request, account.id)
		});
	}

	if (request.method === 'POST' && url.pathname === '/api/me/mfa/setup') {
		if (account.role !== 'admin') throw createError(403, 'Administrator access is required.');
		const existing = await queries.findMfaSecret.get(account.id);
		if (existing && existing.enabled) throw createError(409, 'MFA is already enabled for this account.');
		const secret = generateTotpSecret();
		if (existing) await queries.updateMfaSecret.run(secret, new Date().toISOString(), account.id);
		else await queries.insertMfaSecret.run(account.id, secret, false, new Date().toISOString());
		return sendJson(response, 200, {
			secret,
			otpauthUri: totpOtpauthUri(account.email, secret),
			enabled: false
		});
	}

	if (request.method === 'POST' && url.pathname === '/api/me/mfa/enable') {
		if (account.role !== 'admin') throw createError(403, 'Administrator access is required.');
		const body = await readBody(request);
		const record = await queries.findMfaSecret.get(account.id);
		if (!record) throw createError(404, 'Set up MFA before enabling it.');
		if (record.enabled) throw createError(409, 'MFA is already enabled for this account.');
		if (!verifyTotpCode(record.secret, body.code)) throw createError(401, 'Invalid or expired multi-factor authentication code.');
		await queries.enableMfaSecret.run(account.id);
		await recordAuditEvent(account, 'mfa.enabled');
		return sendJson(response, 200, { enabled: true });
	}

	if (request.method === 'DELETE' && url.pathname === '/api/me/mfa') {
		if (account.role !== 'admin') throw createError(403, 'Administrator access is required.');
		const body = await readBody(request);
		const record = await queries.findMfaSecret.get(account.id);
		if (!record || !record.enabled) throw createError(404, 'MFA is not enabled for this account.');
		if (!verifyTotpCode(record.secret, body.code)) throw createError(401, 'Invalid or expired multi-factor authentication code.');
		await queries.deleteMfaSecret.run(account.id);
		await recordAuditEvent(account, 'mfa.disabled');
		return sendJson(response, 200, { disabled: true });
	}

	if (request.method === 'DELETE' && url.pathname === '/api/me') {
		const body = await readBody(request);
		if (typeof body.password !== 'string' || !(await passwordMatches(body.password, account))) {
			throw createError(401, 'Enter your current password to delete this account.');
		}

		await withTransaction(async () => {
			await recordAuditEvent(account, 'account.deleted', account, { source: 'self_service' });
			await queries.delete.run(account.id);
		});
		return sendJson(response, 200, { ok: true }, { 'Set-Cookie': clearSessionCookie(request) });
	}

	throw createError(404, 'That account endpoint does not exist.');
}

async function initializeDatabase() {
	if (usePostgresBackend()) {
		if (!process.env.DATABASE_URL) throw new Error('DB_BACKEND=postgres requires DATABASE_URL.');
		postgresPool = new Pool({
			connectionString: normalizedPostgresConnectionString(),
			ssl: await postgresSslConfig(),
			max: positiveIntegerSetting('DATABASE_POOL_SIZE', 10),
			connectionTimeoutMillis: 10000,
			idleTimeoutMillis: 30000
		});
		await postgresPool.query('SELECT 1');
		const schema = await fs.readFile(path.join(root, 'supabase', 'migrations', '20261031_initial_schema.sql'), 'utf8');
		await executeScript(schema);
		queries = buildQueries();
		await queries.deleteExpiredSessions.run(Date.now());
		return;
	}

	try {
		await fs.mkdir(path.dirname(databaseFile), { recursive: true });
		database = new DatabaseSync(databaseFile);
		database.exec(`
			PRAGMA journal_mode = WAL;
			PRAGMA foreign_keys = ON;
			CREATE TABLE IF NOT EXISTS accounts (
				id TEXT PRIMARY KEY,
				email TEXT NOT NULL COLLATE NOCASE UNIQUE,
				display_name TEXT NOT NULL,
				created_at TEXT NOT NULL,
				role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
				status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
				email_verified_at TEXT,
				pending_email TEXT COLLATE NOCASE UNIQUE,
				salt TEXT NOT NULL,
				password_hash TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS account_tokens (
				token_hash TEXT PRIMARY KEY,
				account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
				purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'password_reset', 'invite')),
				email TEXT,
				expires_at INTEGER NOT NULL,
				used_at INTEGER
			);
			CREATE INDEX IF NOT EXISTS account_tokens_account_purpose
				ON account_tokens (account_id, purpose, expires_at);
			CREATE TABLE IF NOT EXISTS sessions (
				session_id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				user_agent TEXT NOT NULL DEFAULT ''
			);
			CREATE INDEX IF NOT EXISTS sessions_account_expiry ON sessions (account_id, expires_at);
			CREATE TABLE IF NOT EXISTS audit_events (
				event_id INTEGER PRIMARY KEY AUTOINCREMENT,
				actor_account_id TEXT,
				actor_email TEXT,
				action TEXT NOT NULL,
				affected_account_id TEXT,
				affected_email TEXT,
				occurred_at TEXT NOT NULL,
				metadata_json TEXT NOT NULL DEFAULT '{}'
			);
			CREATE INDEX IF NOT EXISTS audit_events_occurred_at ON audit_events (occurred_at DESC, event_id DESC);
			CREATE INDEX IF NOT EXISTS audit_events_affected ON audit_events (affected_account_id, occurred_at DESC);
			CREATE TABLE IF NOT EXISTS rate_limits (
				bucket_hash TEXT PRIMARY KEY,
				window_started_at INTEGER NOT NULL,
				attempts INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			);
			CREATE INDEX IF NOT EXISTS rate_limits_expiry ON rate_limits (expires_at);
			CREATE TABLE IF NOT EXISTS mfa_secrets (
				account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
				secret TEXT NOT NULL,
				enabled INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			);
		`);
			const accountColumns = database.prepare('PRAGMA table_info(accounts)').all();
			if (!accountColumns.some(column => column.name === 'role')) {
				database.exec("ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'))");
			}
			if (!accountColumns.some(column => column.name === 'status')) {
				database.exec("ALTER TABLE accounts ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended'))");
			}
			if (!accountColumns.some(column => column.name === 'email_verified_at')) {
				database.exec('ALTER TABLE accounts ADD COLUMN email_verified_at TEXT');
			}
			if (!accountColumns.some(column => column.name === 'pending_email')) {
				database.exec('ALTER TABLE accounts ADD COLUMN pending_email TEXT COLLATE NOCASE');
			}
			database.exec('CREATE UNIQUE INDEX IF NOT EXISTS accounts_pending_email ON accounts (pending_email) WHERE pending_email IS NOT NULL');
			database.exec(`
				CREATE TABLE IF NOT EXISTS account_tokens (
					token_hash TEXT PRIMARY KEY,
					account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
					purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'password_reset', 'invite')),
					email TEXT,
					expires_at INTEGER NOT NULL,
					used_at INTEGER
				);
				CREATE INDEX IF NOT EXISTS account_tokens_account_purpose
					ON account_tokens (account_id, purpose, expires_at);
			`);
		queries = buildQueries();
		await queries.deleteExpiredSessions.run(Date.now());
	} catch (error) {
		if (error.code !== 'ENOENT') throw error;
	}

	if ((await queries.count.get()).count > 0) return;
	let savedAccounts;
	try {
		savedAccounts = JSON.parse(await fs.readFile(dataFile, 'utf8'));
	} catch (error) {
		if (error.code === 'ENOENT') return;
		throw error;
	}
	if (!Array.isArray(savedAccounts)) throw new Error('Legacy account data must be an array.');

	await withTransaction(async () => {
		const insertLegacy = prepareQuery(`
			INSERT OR IGNORE INTO accounts (id, email, display_name, created_at, role, status, salt, password_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`);
		for (const account of savedAccounts) {
			await insertLegacy.run(account.id, account.email, account.displayName, account.createdAt, account.role || 'user', account.status || 'active', account.salt, account.passwordHash);
		}
	});
}

async function promoteFirstAdmin(email) {
	const normalizedEmail = normalizeEmail(email);
	if (!validateEmail(normalizedEmail)) throw new Error('Provide a valid email address for an existing account.');

	let account;
	await withTransaction(async () => {
		if ((await queries.adminCount.get()).count > 0) {
			throw new Error('An administrator already exists; first-admin promotion is one-time.');
		}
		account = await queries.findByEmail.get(normalizedEmail);
		if (!account) throw new Error('No account found for that email. Register the account before promoting it.');
		await queries.updateRole.run('admin', account.id);
		await recordAuditEvent(null, 'role.changed', account, { from: 'user', to: 'admin', source: 'first_admin_setup' });
	});
	console.log(`Promoted ${account.email} to the first administrator.`);
}

function validateProductionConfig() {
	if (process.env.NODE_ENV !== 'production') return;
	let publicUrl;
	try {
		publicUrl = new URL(process.env.APP_BASE_URL || '');
	} catch {
		throw new Error('Production requires APP_BASE_URL to be a valid HTTPS URL.');
	}
	if (publicUrl.protocol !== 'https:') {
		throw new Error('Production requires APP_BASE_URL to use HTTPS.');
	}
	if (!process.env.DATABASE_URL) {
		throw new Error('Production requires DATABASE_URL for Supabase Postgres.');
	}
	if (!process.env.DATABASE_SSL_CA) {
		throw new Error('Production requires DATABASE_SSL_CA to verify the Supabase database certificate.');
	}
	if (!usePostgresBackend()) {
		throw new Error('Production requires DB_BACKEND=postgres.');
	}
	if (process.env.TRUST_PROXY !== 'true') {
		throw new Error('Production requires TRUST_PROXY=true behind the HTTPS reverse proxy.');
	}
	if (!process.env.SMTP_HOST || !process.env.MAIL_FROM) {
		throw new Error('Production requires SMTP_HOST and MAIL_FROM for account email.');
	}
}

async function start() {
	validateProductionConfig();
	await initializeDatabase();
	dummyPasswordCredentials = await hashPassword(randomBytes(32).toString('hex'));
	const server = http.createServer(async (request, response) => {
		const url = new URL(request.url, 'http://localhost');

		if (request.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/audit' || url.pathname === '/sessions')) {
			const account = await getAccountForRequest(request);
			if (!account) return sendJson(response, 401, { error: 'Please sign in to continue.' });
			if ((url.pathname === '/admin' || url.pathname === '/admin/audit') && account.role !== 'admin') {
				return sendJson(response, 403, { error: 'Administrator access is required.' });
			}
		}

		if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html' || url.pathname === '/admin' || url.pathname === '/admin/audit' || url.pathname === '/sessions')) {
			try {
				const page = await fs.readFile(path.join(root, 'index.html'));
				response.writeHead(200, {
					'Content-Type': 'text/html; charset=utf-8',
					'Cache-Control': 'no-store',
					'X-Content-Type-Options': 'nosniff',
					'Referrer-Policy': 'same-origin'
				});
				return response.end(page);
			} catch {
				return sendJson(response, 500, { error: 'The application page could not be loaded.' });
			}
		}

		if (url.pathname.startsWith('/api/')) {
			try {
				return await handleApi(request, response, url);
			} catch (error) {
				const status = error.status || 500;
				if (status >= 500) console.error(error);
				return sendJson(response, status, {
					error: status >= 500 ? 'A server error occurred.' : error.message
				}, error.retryAfterSeconds ? { 'Retry-After': String(error.retryAfterSeconds) } : {});
			}
		}

		return sendJson(response, 404, { error: 'Page not found.' });
	});

	const port = Number(process.env.PORT) || 3000;
	const host = process.env.HOST || '127.0.0.1';
	server.listen(port, host, () => {
		console.log(`Account desk is running at http://${host}:${port}`);
	});
}

async function main() {
	if (process.argv[2] === 'promote-admin') {
		if (process.argv.length !== 4) {
			throw new Error('Usage: npm run promote-admin -- <existing-account-email>');
		}
		await initializeDatabase();
		return promoteFirstAdmin(process.argv[3]);
	}
	return start();
}

main().catch(error => {
	console.error('Account desk:', error.message);
	process.exitCode = 1;
});
