const http = require('node:http');
const { createHash, randomBytes, scrypt: scryptCallback, timingSafeEqual } = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
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
const rateLimitWindowMs = positiveIntegerSetting('RATE_LIMIT_WINDOW_MS', 15 * 60 * 1000);
let database;
let queries;
let mailTransport;
let dummyPasswordCredentials;

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

function positiveIntegerSetting(name, fallback) {
	const value = Number(process.env[name]);
	return Number.isSafeInteger(value) && value > 0 ? value : fallback;
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

function getAccountForRequest(request) {
	const cookie = request.headers.cookie || '';
	const token = cookie.match(/(?:^|;\s*)session=([a-f0-9]+)/)?.[1];
	if (!token) return null;

	const tokenHash = hashToken(token);
	const session = queries.findSessionByToken.get(tokenHash);
	if (!session || session.expires_at <= Date.now()) {
		if (session) queries.deleteSessionByToken.run(tokenHash);
		return null;
	}

	const account = accountFromRow(queries.findById.get(session.account_id));
 	return account?.status === 'active' ? account : null;
}

function getSessionToken(request) {
	return (request.headers.cookie || '').match(/(?:^|;\s*)session=([a-f0-9]+)/)?.[1] || null;
}

function issueSession(accountId, userAgent = '') {
	const token = randomBytes(32).toString('hex');
	const now = Date.now();
	queries.insertSession.run(randomBytes(16).toString('hex'), hashToken(token), accountId, now, now + sessionLifetime, userAgent.slice(0, 300));
	return token;
}

function sessionCookieForRequest(request, accountId) {
	return sessionCookie(
		issueSession(accountId, request.headers['user-agent'] || ''),
		Math.floor(sessionLifetime / 1000),
		isSecureRequest(request)
	);
}

function consumeRateLimit(request, scope, identifier, limit) {
	const forwardedAddress = process.env.TRUST_PROXY === 'true'
		? request.headers['x-forwarded-for']?.split(',')[0].trim()
		: undefined;
	const address = forwardedAddress || request.socket.remoteAddress || 'unknown';
	const rawBucket = identifier === undefined ? `ip:${address}` : `identifier:${identifier}`;
	const bucketHash = hashToken(`${scope}\0${rawBucket}`);
	const now = Date.now();
	let retryAfterSeconds = 0;

	database.exec('BEGIN IMMEDIATE');
	try {
		const bucket = queries.findRateLimit.get(bucketHash);
		if (!bucket || bucket.expires_at <= now) {
			queries.resetRateLimit.run(bucketHash, now, now + rateLimitWindowMs);
		} else if (bucket.attempts >= limit) {
			retryAfterSeconds = Math.max(1, Math.ceil((bucket.expires_at - now) / 1000));
		} else {
			queries.incrementRateLimit.run(bucketHash);
		}
		queries.deleteExpiredRateLimits.run(now);
		database.exec('COMMIT');
	} catch (error) {
		database.exec('ROLLBACK');
		throw error;
	}

	if (retryAfterSeconds) {
		throw createError(429, 'Too many requests. Please try again later.', retryAfterSeconds);
	}
}

function recordAuditEvent(actor, action, affectedAccount = actor, metadata = {}) {
	queries.insertAuditEvent.run(
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

function createAccountToken(accountId, purpose, email, lifetime) {
	const token = randomBytes(32).toString('base64url');
	const now = Date.now();
	database.prepare('DELETE FROM account_tokens WHERE account_id = ? AND purpose = ? AND used_at IS NULL').run(accountId, purpose);
	database.prepare(`
		INSERT INTO account_tokens (token_hash, account_id, purpose, email, expires_at, used_at)
		VALUES (?, ?, ?, ?, ?, NULL)
	`).run(hashToken(token), accountId, purpose, email, now + lifetime);
	return token;
}

function accountActionUrl(purpose, token) {
	const baseUrl = process.env.APP_BASE_URL || `http://localhost:${Number(process.env.PORT) || 3000}`;
	const url = new URL('/', baseUrl);
	url.searchParams.set(purpose === 'verify_email' ? 'verify' : 'reset', token);
	return url.toString();
}

async function sendAccountEmail(purpose, email, token) {
	const url = accountActionUrl(purpose, token);
	const verification = purpose === 'verify_email';
	const subject = verification ? 'Verify your email address' : 'Reset your password';
	const action = verification ? 'Verify your email address' : 'Choose a new password';
	const text = `${action}: ${url}\n\nThis link expires in ${verification ? '24 hours' : '15 minutes'} and can only be used once.`;

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
		await mailTransport.sendMail({ from: process.env.MAIL_FROM, to: email, subject, text });
		return;
	}

	if (process.env.NODE_ENV === 'production') {
		throw createError(503, 'Email delivery is not configured. Set SMTP_HOST and MAIL_FROM.');
	}
	console.log(`[DEV EMAIL ${purpose}] ${email} ${url}`);
}

function readRedeemableToken(token, purpose) {
	if (typeof token !== 'string' || token.length > 128) throw createError(400, 'This link is invalid.');
	const record = queries.findToken.get(hashToken(token));
	if (!record || record.purpose !== purpose) throw createError(400, 'This link is invalid.');
	if (record.used_at !== null) throw createError(409, 'This link has already been used.');
	if (record.expires_at <= Date.now()) throw createError(410, 'This link has expired.');
	return record;
}

function verifyEmailToken(token) {
	database.exec('BEGIN IMMEDIATE');
	try {
		const record = readRedeemableToken(token, 'verify_email');
		const account = accountFromRow(queries.findById.get(record.account_id));
		if (!account || (account.email !== record.email && account.pendingEmail !== record.email)) {
			throw createError(400, 'This verification link is invalid.');
		}
		if (account.pendingEmail === record.email) {
			const owner = queries.findEmailOwner.get(record.email, record.email, account.id);
			if (owner) throw createError(409, 'That email address is already associated with another account.');
		}
		queries.verifyEmail.run(record.email, new Date().toISOString(), account.id);
		queries.markTokenUsed.run(Date.now(), record.token_hash);
		database.exec('COMMIT');
		return account;
	} catch (error) {
		database.exec('ROLLBACK');
		throw error;
	}
}

async function resetPasswordWithToken(token, password) {
	if (!validatePassword(password)) throw createError(400, 'Password must be between 10 and 200 characters.');
	const initialRecord = readRedeemableToken(token, 'password_reset');
	const account = accountFromRow(queries.findById.get(initialRecord.account_id));
	if (!account || account.status !== 'active') throw createError(400, 'This link is invalid.');
	const credentials = await hashPassword(password);

	database.exec('BEGIN IMMEDIATE');
	try {
		const record = readRedeemableToken(token, 'password_reset');
		if (record.account_id !== account.id) throw createError(400, 'This link is invalid.');
		queries.updatePassword.run(credentials.salt, credentials.passwordHash, account.id);
		queries.markTokenUsed.run(Date.now(), record.token_hash);
		queries.deleteAccountSessions.run(account.id);
		recordAuditEvent(account, 'password.reset');
		database.exec('COMMIT');
	} catch (error) {
		database.exec('ROLLBACK');
		throw error;
	}
}

async function handleApi(request, response, url) {
	if (url.pathname.startsWith('/api/admin/audit-events')) {
		const administrator = getAccountForRequest(request);
		if (!administrator) throw createError(401, 'Please sign in to continue.');
		if (administrator.role !== 'admin') throw createError(403, 'Administrator access is required.');
		if (request.method !== 'GET' || url.pathname !== '/api/admin/audit-events') {
			throw createError(404, 'That audit endpoint does not exist.');
		}

		const search = (url.searchParams.get('q') || '').trim().slice(0, 100);
		const requestedLimit = Number(url.searchParams.get('limit')) || 20;
		const requestedOffset = Number(url.searchParams.get('offset')) || 0;
		const limit = Math.min(100, Math.max(1, Math.floor(requestedLimit)));
		const offset = Math.min(1000000, Math.max(0, Math.floor(requestedOffset)));
		const filters = [search, search, search, search, search, search];
		const total = queries.countAuditEvents.get(...filters).count;
		const events = queries.listAuditEvents.all(...filters, limit, offset).map(event => ({
			id: event.event_id,
			actorAccountId: event.actor_account_id,
			actorEmail: event.actor_email,
			action: event.action,
			affectedAccountId: event.affected_account_id,
			affectedEmail: event.affected_email,
			occurredAt: event.occurred_at,
			metadata: JSON.parse(event.metadata_json)
		}));
		return sendJson(response, 200, { events, total, limit, offset });
	}

	if (request.method === 'POST' && url.pathname === '/api/email/verify') {
		const body = await readBody(request);
		const account = verifyEmailToken(body.token);
		return sendJson(response, 200, { verified: true, account: publicAccount(accountFromRow(queries.findById.get(account.id))) });
	}

	if (request.method === 'POST' && url.pathname === '/api/password-reset/request') {
		consumeRateLimit(request, 'password-reset:ip', undefined, positiveIntegerSetting('RATE_LIMIT_PASSWORD_RESET_IP_MAX', 10));
		const body = await readBody(request);
		const email = normalizeEmail(body.email);
		if (validateEmail(email)) {
			consumeRateLimit(request, 'password-reset:email', email, positiveIntegerSetting('RATE_LIMIT_PASSWORD_RESET_EMAIL_MAX', 4));
		}
		const account = accountFromRow(queries.findByEmail.get(email));
		if (account && account.status === 'active' && account.emailVerifiedAt) {
			const token = createAccountToken(account.id, 'password_reset', account.email, resetLifetime);
			try {
				await sendAccountEmail('password_reset', account.email, token);
			} catch {
				console.error('Password reset email delivery failed.');
			}
		}
		return sendJson(response, 200, { message: 'If that verified email belongs to an account, a reset link has been sent.' });
	}

	if (request.method === 'POST' && url.pathname === '/api/password-reset/complete') {
		const body = await readBody(request);
		await resetPasswordWithToken(body.token, body.password);
		return sendJson(response, 200, { message: 'Your password has been reset. Sign in with your new password.' });
	}

	if (url.pathname.startsWith('/api/admin/accounts')) {
		const administrator = getAccountForRequest(request);
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
			const total = queries.countAccounts.get(...filters).count;
			const accountList = queries.listAccounts.all(...filters, limit, offset)
				.map(row => publicAccount(accountFromRow(row)));
			return sendJson(response, 200, { accounts: accountList, total, limit, offset });
		}

		const roleMatch = url.pathname.match(/^\/api\/admin\/accounts\/([a-f0-9]+)\/role$/);
		if (request.method === 'PATCH' && roleMatch) {
			const body = await readBody(request);
			if (!['user', 'admin'].includes(body.role)) throw createError(400, 'Role must be user or admin.');
			const target = accountFromRow(queries.findById.get(roleMatch[1]));
			if (!target) throw createError(404, 'Account not found.');

			database.exec('BEGIN IMMEDIATE');
			try {
				if (target.role === 'admin' && body.role === 'user' && queries.adminCount.get().count <= 1) {
					throw createError(409, 'The last administrator cannot be demoted.');
				}
				if (target.role !== body.role) {
					queries.updateRole.run(body.role, target.id);
					recordAuditEvent(administrator, 'role.changed', target, { from: target.role, to: body.role });
				}
				database.exec('COMMIT');
			} catch (error) {
				database.exec('ROLLBACK');
				throw error;
			}
			return sendJson(response, 200, { account: { ...publicAccount(target), role: body.role } });
		}

		const statusMatch = url.pathname.match(/^\/api\/admin\/accounts\/([a-f0-9]+)\/status$/);
		if (request.method === 'PATCH' && statusMatch) {
			const body = await readBody(request);
			if (!['active', 'suspended'].includes(body.status)) {
				throw createError(400, 'Status must be active or suspended.');
			}
			const target = accountFromRow(queries.findById.get(statusMatch[1]));
			if (!target) throw createError(404, 'Account not found.');
			if (target.id === administrator.id && body.status === 'suspended') {
				throw createError(409, 'You cannot suspend your own administrator account.');
			}

			database.exec('BEGIN IMMEDIATE');
			try {
				if (target.role === 'admin' && body.status === 'suspended' && queries.activeAdminCount.get().count <= 1) {
					throw createError(409, 'The last active administrator cannot be suspended.');
				}
				if (target.status !== body.status) {
					queries.updateStatus.run(body.status, target.id);
					if (body.status === 'suspended') queries.deleteAccountSessions.run(target.id);
					const action = body.status === 'suspended' ? 'account.suspended' : 'account.reactivated';
					recordAuditEvent(administrator, action, target, { from: target.status, to: body.status });
				}
				database.exec('COMMIT');
			} catch (error) {
				database.exec('ROLLBACK');
				throw error;
			}
			return sendJson(response, 200, { account: { ...publicAccount(target), status: body.status } });
		}

		throw createError(404, 'That admin endpoint does not exist.');
	}

	if (request.method === 'POST' && url.pathname === '/api/register') {
		consumeRateLimit(request, 'registration:ip', undefined, positiveIntegerSetting('RATE_LIMIT_REGISTRATION_IP_MAX', 15));
		const body = await readBody(request);
		const email = normalizeEmail(body.email);
		const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';

		if (!displayName || displayName.length > 80) throw createError(400, 'Enter a name of 1 to 80 characters.');
		if (!validateEmail(email)) throw createError(400, 'Enter a valid email address.');
		if (!validatePassword(body.password)) throw createError(400, 'Password must be between 10 and 200 characters.');
		consumeRateLimit(request, 'registration:email', email, positiveIntegerSetting('RATE_LIMIT_REGISTRATION_EMAIL_MAX', 3));
		if (queries.findByEmail.get(email)) {
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
			queries.insert.run(account.id, account.email, account.displayName, account.createdAt, account.role, account.status, account.salt, account.passwordHash);
		} catch (error) {
			if (error.message.includes('UNIQUE constraint failed')) {
				throw createError(409, 'An account already uses that email address.');
			}
			throw error;
		}
		const verificationToken = createAccountToken(account.id, 'verify_email', account.email, verificationLifetime);
		await sendAccountEmail('verify_email', account.email, verificationToken);
		return sendJson(response, 201, { account: publicAccount(account) }, {
			'Set-Cookie': sessionCookieForRequest(request, account.id)
		});
	}

	if (request.method === 'POST' && url.pathname === '/api/login') {
		consumeRateLimit(request, 'sign-in:ip', undefined, positiveIntegerSetting('RATE_LIMIT_SIGN_IN_IP_MAX', 20));
		const body = await readBody(request);
		const email = normalizeEmail(body.email);
		if (validateEmail(email)) {
			consumeRateLimit(request, 'sign-in:email', email, positiveIntegerSetting('RATE_LIMIT_SIGN_IN_EMAIL_MAX', 8));
		}
		const account = accountFromRow(queries.findByEmail.get(email));
		const password = typeof body.password === 'string' ? body.password : '';
		const validPassword = await passwordMatches(password, account || dummyPasswordCredentials);
		if (!account || !validPassword || account.status !== 'active') {
			throw createError(401, 'Email or password is incorrect.');
		}

		recordAuditEvent(account, 'sign_in.succeeded');
		return sendJson(response, 200, { account: publicAccount(account) }, {
			'Set-Cookie': sessionCookieForRequest(request, account.id)
		});
	}

	if (request.method === 'POST' && url.pathname === '/api/logout') {
		const token = getSessionToken(request);
		if (token) queries.deleteSessionByToken.run(hashToken(token));
		return sendJson(response, 200, { ok: true }, { 'Set-Cookie': clearSessionCookie(request) });
	}

	const account = getAccountForRequest(request);
	if (!account) throw createError(401, 'Please sign in to continue.');

	if (request.method === 'GET' && url.pathname === '/api/me') {
		return sendJson(response, 200, { account: publicAccount(account) });
	}

	if (request.method === 'GET' && url.pathname === '/api/me/sessions') {
		const currentToken = getSessionToken(request);
		const currentHash = currentToken ? hashToken(currentToken) : null;
		const activeSessions = queries.listSessions.all(account.id, Date.now()).map(session => ({
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
		const session = queries.findSessionById.get(sessionMatch[1], account.id, Date.now());
		if (!session) throw createError(404, 'Active session not found.');
		const current = session.token_hash === hashToken(getSessionToken(request) || '');
		queries.deleteSessionById.run(session.session_id, account.id);
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
			if (queries.findEmailOwner.get(email, email, account.id)) {
				throw createError(409, 'An account already uses that email address.');
			}
		}
		const changedFields = [];
		if (displayName !== account.displayName) changedFields.push('displayName');
		if (changingEmail) changedFields.push('email');
		database.exec('BEGIN IMMEDIATE');
		try {
			queries.update.run(displayName, account.id);
			if (changingEmail) queries.updatePendingEmail.run(email, account.id);
			if (changedFields.length > 0) {
				recordAuditEvent(account, 'profile.updated', account, { changedFields });
			}
			database.exec('COMMIT');
		} catch (error) {
			database.exec('ROLLBACK');
			if (error.message.includes('UNIQUE constraint failed')) {
				throw createError(409, 'An account already uses that email address.');
			}
			throw error;
		}
		account.displayName = displayName;
		if (changingEmail) {
			account.pendingEmail = email;
			const verificationToken = createAccountToken(account.id, 'verify_email', email, verificationLifetime);
			await sendAccountEmail('verify_email', email, verificationToken);
		}
		return sendJson(response, 200, { account: publicAccount(account) });
	}

	if (request.method === 'POST' && url.pathname === '/api/me/verification-email') {
		if (account.emailVerifiedAt && !account.pendingEmail) {
			throw createError(409, 'Your current email address is already verified.');
		}
		const email = account.pendingEmail || account.email;
		const token = createAccountToken(account.id, 'verify_email', email, verificationLifetime);
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
		database.exec('BEGIN IMMEDIATE');
		try {
			queries.updatePassword.run(credentials.salt, credentials.passwordHash, account.id);
			queries.invalidateAccountTokens.run(account.id);
			queries.deleteAccountSessions.run(account.id);
			recordAuditEvent(account, 'password.changed');
			database.exec('COMMIT');
		} catch (error) {
			database.exec('ROLLBACK');
			throw error;
		}
		return sendJson(response, 200, { message: 'Password changed successfully.' }, {
			'Set-Cookie': sessionCookieForRequest(request, account.id)
		});
	}

	if (request.method === 'DELETE' && url.pathname === '/api/me') {
		const body = await readBody(request);
		if (typeof body.password !== 'string' || !(await passwordMatches(body.password, account))) {
			throw createError(401, 'Enter your current password to delete this account.');
		}

		database.exec('BEGIN IMMEDIATE');
		try {
			recordAuditEvent(account, 'account.deleted', account, { source: 'self_service' });
			queries.delete.run(account.id);
			database.exec('COMMIT');
		} catch (error) {
			database.exec('ROLLBACK');
			throw error;
		}
		return sendJson(response, 200, { ok: true }, { 'Set-Cookie': clearSessionCookie(request) });
	}

	throw createError(404, 'That account endpoint does not exist.');
}

async function initializeDatabase() {
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
				purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'password_reset')),
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
					purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'password_reset')),
					email TEXT,
					expires_at INTEGER NOT NULL,
					used_at INTEGER
				);
				CREATE INDEX IF NOT EXISTS account_tokens_account_purpose
					ON account_tokens (account_id, purpose, expires_at);
			`);
		queries = {
			findById: database.prepare('SELECT * FROM accounts WHERE id = ?'),
			findByEmail: database.prepare('SELECT * FROM accounts WHERE email = ?'),
			insertSession: database.prepare(`
				INSERT INTO sessions (session_id, token_hash, account_id, created_at, expires_at, user_agent)
				VALUES (?, ?, ?, ?, ?, ?)
			`),
			findSessionByToken: database.prepare('SELECT * FROM sessions WHERE token_hash = ?'),
			deleteSessionByToken: database.prepare('DELETE FROM sessions WHERE token_hash = ?'),
			listSessions: database.prepare('SELECT * FROM sessions WHERE account_id = ? AND expires_at > ? ORDER BY created_at DESC'),
			findSessionById: database.prepare('SELECT * FROM sessions WHERE session_id = ? AND account_id = ? AND expires_at > ?'),
			deleteSessionById: database.prepare('DELETE FROM sessions WHERE session_id = ? AND account_id = ?'),
			deleteAccountSessions: database.prepare('DELETE FROM sessions WHERE account_id = ?'),
			deleteExpiredSessions: database.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
			findRateLimit: database.prepare('SELECT * FROM rate_limits WHERE bucket_hash = ?'),
			resetRateLimit: database.prepare(`
				INSERT INTO rate_limits (bucket_hash, window_started_at, attempts, expires_at)
				VALUES (?, ?, 1, ?)
				ON CONFLICT(bucket_hash) DO UPDATE SET
					window_started_at = excluded.window_started_at,
					attempts = 1,
					expires_at = excluded.expires_at
			`),
			incrementRateLimit: database.prepare('UPDATE rate_limits SET attempts = attempts + 1 WHERE bucket_hash = ?'),
			deleteExpiredRateLimits: database.prepare('DELETE FROM rate_limits WHERE expires_at <= ?'),
			insertAuditEvent: database.prepare(`
				INSERT INTO audit_events (
					actor_account_id, actor_email, action, affected_account_id,
					affected_email, occurred_at, metadata_json
				) VALUES (?, ?, ?, ?, ?, ?, ?)
			`),
			countAuditEvents: database.prepare(`
				SELECT COUNT(*) AS count FROM audit_events
				WHERE (? = '' OR instr(lower(action), lower(?)) > 0
					OR instr(lower(actor_email), lower(?)) > 0
					OR instr(lower(affected_email), lower(?)) > 0
					OR instr(lower(COALESCE(actor_account_id, '')), lower(?)) > 0
					OR instr(lower(COALESCE(affected_account_id, '')), lower(?)) > 0)
			`),
			listAuditEvents: database.prepare(`
				SELECT * FROM audit_events
				WHERE (? = '' OR instr(lower(action), lower(?)) > 0
					OR instr(lower(actor_email), lower(?)) > 0
					OR instr(lower(affected_email), lower(?)) > 0
					OR instr(lower(COALESCE(actor_account_id, '')), lower(?)) > 0
					OR instr(lower(COALESCE(affected_account_id, '')), lower(?)) > 0)
				ORDER BY occurred_at DESC, event_id DESC
				LIMIT ? OFFSET ?
			`),
				findEmailOwner: database.prepare('SELECT id FROM accounts WHERE (email = ? OR pending_email = ?) AND id <> ?'),
			insert: database.prepare(`
				INSERT INTO accounts (id, email, display_name, created_at, role, status, salt, password_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`),
			update: database.prepare('UPDATE accounts SET display_name = ? WHERE id = ?'),
			updatePendingEmail: database.prepare('UPDATE accounts SET pending_email = ? WHERE id = ?'),
			verifyEmail: database.prepare('UPDATE accounts SET email = ?, pending_email = NULL, email_verified_at = ? WHERE id = ?'),
			updatePassword: database.prepare('UPDATE accounts SET salt = ?, password_hash = ? WHERE id = ?'),
			updateRole: database.prepare('UPDATE accounts SET role = ? WHERE id = ?'),
			updateStatus: database.prepare('UPDATE accounts SET status = ? WHERE id = ?'),
			delete: database.prepare('DELETE FROM accounts WHERE id = ?'),
				count: database.prepare('SELECT COUNT(*) AS count FROM accounts'),
				adminCount: database.prepare("SELECT COUNT(*) AS count FROM accounts WHERE role = 'admin'"),
			activeAdminCount: database.prepare("SELECT COUNT(*) AS count FROM accounts WHERE role = 'admin' AND status = 'active'"),
			findToken: database.prepare('SELECT * FROM account_tokens WHERE token_hash = ?'),
			markTokenUsed: database.prepare('UPDATE account_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL'),
			invalidateAccountTokens: database.prepare('DELETE FROM account_tokens WHERE account_id = ? AND used_at IS NULL'),
			countAccounts: database.prepare(`
				SELECT COUNT(*) AS count FROM accounts
				WHERE (? = '' OR instr(lower(display_name), lower(?)) > 0 OR instr(lower(email), lower(?)) > 0)
				AND (? = 'all' OR status = ?)
			`),
			listAccounts: database.prepare(`
				SELECT * FROM accounts
				WHERE (? = '' OR instr(lower(display_name), lower(?)) > 0 OR instr(lower(email), lower(?)) > 0)
				AND (? = 'all' OR status = ?)
				ORDER BY created_at DESC, id
				LIMIT ? OFFSET ?
			`)
		};
		queries.deleteExpiredSessions.run(Date.now());
	} catch (error) {
		if (error.code !== 'ENOENT') throw error;
	}

	if (queries.count.get().count > 0) return;
	let savedAccounts;
	try {
		savedAccounts = JSON.parse(await fs.readFile(dataFile, 'utf8'));
	} catch (error) {
		if (error.code === 'ENOENT') return;
		throw error;
	}
	if (!Array.isArray(savedAccounts)) throw new Error('Legacy account data must be an array.');

	const insertLegacy = database.prepare(`
		INSERT OR IGNORE INTO accounts (id, email, display_name, created_at, role, status, salt, password_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`);
	database.exec('BEGIN');
	try {
		for (const account of savedAccounts) {
			insertLegacy.run(account.id, account.email, account.displayName, account.createdAt, account.role || 'user', account.status || 'active', account.salt, account.passwordHash);
		}
		database.exec('COMMIT');
	} catch (error) {
		database.exec('ROLLBACK');
		throw error;
	}
}

async function promoteFirstAdmin(email) {
	const normalizedEmail = normalizeEmail(email);
	if (!validateEmail(normalizedEmail)) throw new Error('Provide a valid email address for an existing account.');

	database.exec('BEGIN IMMEDIATE');
	try {
		if (queries.adminCount.get().count > 0) {
			throw new Error('An administrator already exists; first-admin promotion is one-time.');
		}
		const account = queries.findByEmail.get(normalizedEmail);
		if (!account) throw new Error('No account found for that email. Register the account before promoting it.');
		database.prepare("UPDATE accounts SET role = 'admin' WHERE id = ?").run(account.id);
		recordAuditEvent(null, 'role.changed', account, { from: 'user', to: 'admin', source: 'first_admin_setup' });
		database.exec('COMMIT');
		console.log(`Promoted ${account.email} to the first administrator.`);
	} catch (error) {
		database.exec('ROLLBACK');
		throw error;
	}
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
			const account = getAccountForRequest(request);
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
