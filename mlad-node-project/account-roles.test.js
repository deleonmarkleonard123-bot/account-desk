const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const { createHash, createHmac } = require('node:crypto');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { after, before, test } = require('node:test');

const serverFile = path.join(__dirname, 'server.js');
let temporaryDirectory;
let databaseFile;
let serverProcess;
let baseUrl;
let smtpServer;
let smtpPort;
let appPort;
const smtpMessages = [];

async function getFreePort() {
	const probe = net.createServer();
	probe.listen(0, '127.0.0.1');
	await once(probe, 'listening');
	const { port } = probe.address();
	await new Promise((resolve, reject) => probe.close(error => error ? reject(error) : resolve()));
	return port;
}

async function waitForServer() {
	for (let attempt = 0; attempt < 50; attempt += 1) {
		if (serverProcess.exitCode !== null) throw new Error('Test server exited before becoming ready.');
		try {
			const response = await fetch(`${baseUrl}/api/me`);
			if (response.status === 401) return;
		} catch {}
		await new Promise(resolve => setTimeout(resolve, 50));
	}
	throw new Error('Test server did not start in time.');
}

async function startTestSmtp() {
	smtpServer = net.createServer(socket => {
		let input = '';
		let message = null;
		socket.write('220 test-mail.local ESMTP\r\n');
		socket.on('error', () => {});
		socket.on('data', chunk => {
			input += chunk.toString('utf8');
			let lineEnd;
			while ((lineEnd = input.indexOf('\n')) >= 0) {
				const line = input.slice(0, lineEnd).replace(/\r$/, '');
				input = input.slice(lineEnd + 1);
				if (message !== null) {
					if (line === '.') {
						smtpMessages.push(message);
						message = null;
						socket.write('250 Message accepted\r\n');
					} else {
						message += `${line.replace(/^\.\./, '.')}\n`;
					}
					continue;
				}

				const command = line.split(' ')[0].toUpperCase();
				if (command === 'EHLO' || command === 'HELO') socket.write('250-test-mail.local\r\n250 SIZE 1000000\r\n');
				else if (command === 'DATA') {
					message = '';
					socket.write('354 End data with <CR><LF>.<CR><LF>\r\n');
				} else if (command === 'QUIT') socket.end('221 Bye\r\n');
				else socket.write('250 OK\r\n');
			}
		});
	});
	const port = await getFreePort();
	smtpServer.listen(port, '127.0.0.1');
	await once(smtpServer, 'listening');
	return port;
}

function latestEmailToken(purpose, email) {
	const subject = purpose === 'verify_email'
		? 'Verify your email address'
		: purpose === 'password_reset'
			? 'Reset your password'
			: 'You are invited to Account Desk';
	const message = [...smtpMessages].reverse().find(item => item.includes(email) && item.includes(subject));
	assert.ok(message, `Expected ${purpose} email for ${email}`);
	const decodedMessage = message
		.replace(/=\n/g, '')
		.replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
	const tokenKey = purpose === 'verify_email' ? 'verify' : purpose === 'password_reset' ? 'reset' : 'invite';
	const token = decodedMessage.match(new RegExp(`${tokenKey}=([A-Za-z0-9_-]+)`))?.[1];
	assert.ok(token, `Expected a token link in the ${purpose} email`);
	return token;
}

function totpCode(secret, time = Date.now()) {
	const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	const normalized = secret.replace(/\s+/g, '').toUpperCase();
	const bytes = [];
	let bits = 0;
	let bitCount = 0;
	for (const character of normalized) {
		const value = base32Chars.indexOf(character);
		assert.notEqual(value, -1, 'Invalid base32 secret');
		bits = (bits << 5) | value;
		bitCount += 5;
		while (bitCount >= 8) {
			bitCount -= 8;
			bytes.push((bits >> bitCount) & 0xff);
		}
	}
	const counter = Math.floor(time / 30000);
	const buffer = Buffer.alloc(8);
	let value = counter;
	for (let index = 7; index >= 0; index -= 1) {
		buffer[index] = value & 0xff;
		value = Math.floor(value / 256);
	}
	const digest = createHmac('sha1', Buffer.from(bytes)).update(buffer).digest();
	const offset = digest[digest.length - 1] & 0x0f;
	const binary = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff);
	return String(binary % 1000000).padStart(6, '0');
}

function runPromotion(email) {
	return spawnSync(process.execPath, [serverFile, 'promote-admin', email], {
		encoding: 'utf8',
		env: { ...process.env, DB_BACKEND: 'sqlite', DB_PATH: databaseFile }
	});
}

async function startAppServer() {
	serverProcess = spawn(process.execPath, [serverFile], {
		stdio: 'ignore',
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(appPort),
			APP_BASE_URL: 'https://accounts.example.test',
			DB_PATH: databaseFile,
			DB_BACKEND: 'sqlite',
			NODE_ENV: 'test',
			SMTP_HOST: '127.0.0.1',
			SMTP_PORT: String(smtpPort),
			MAIL_FROM: 'Account Desk <no-reply@example.test>',
			TRUST_PROXY: 'true'
		}
	});
	await waitForServer();
}

async function stopAppServer() {
	if (serverProcess && serverProcess.exitCode === null) {
		serverProcess.kill('SIGTERM');
		await once(serverProcess, 'exit');
	}
}

before(async () => {
	temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'account-roles-'));
	databaseFile = path.join(temporaryDirectory, 'accounts.sqlite');
	smtpPort = await startTestSmtp();
	appPort = await getFreePort();
	baseUrl = `http://127.0.0.1:${appPort}`;
	await startAppServer();
});

after(async () => {
	await stopAppServer();
	if (smtpServer) {
		smtpServer.close();
		await once(smtpServer, 'close');
	}
	if (temporaryDirectory) await fs.rm(temporaryDirectory, { recursive: true, force: true });
});

test('only the first promoted administrator can access admin routes', async () => {
	let response = await fetch(`${baseUrl}/api/admin/accounts`);
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/admin`);
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/api/admin/audit-events`);
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/admin/audit`);
	assert.equal(response.status, 401);

	response = await fetch(`${baseUrl}/api/register`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			displayName: 'Regular User',
			email: 'regular@example.com',
			password: 'regular-account-password'
		})
	});
	assert.equal(response.status, 201);
	const registration = await response.json();
	assert.equal(registration.account.role, 'user');
	const registrationSetCookie = response.headers.get('set-cookie');
	assert.match(registrationSetCookie, /HttpOnly/);
	assert.match(registrationSetCookie, /SameSite=Strict/);
	assert.doesNotMatch(registrationSetCookie, /; Secure/);
	const userCookie = registrationSetCookie.split(';')[0];

	response = await fetch(`${baseUrl}/api/admin/accounts`, { headers: { Cookie: userCookie } });
	assert.equal(response.status, 403);
	response = await fetch(`${baseUrl}/admin`, { headers: { Cookie: userCookie } });
	assert.equal(response.status, 403);
	response = await fetch(`${baseUrl}/api/admin/audit-events`, { headers: { Cookie: userCookie } });
	assert.equal(response.status, 403);
	response = await fetch(`${baseUrl}/api/admin/audit-events`, {
		method: 'POST',
		headers: { Cookie: userCookie, 'Content-Type': 'application/json' },
		body: '{}'
	});
	assert.equal(response.status, 403);
	response = await fetch(`${baseUrl}/admin/audit`, { headers: { Cookie: userCookie } });
	assert.equal(response.status, 403);

	const promotion = runPromotion('regular@example.com');
	assert.equal(promotion.status, 0, promotion.stderr || promotion.stdout);

	response = await fetch(`${baseUrl}/api/admin/accounts`, { headers: { Cookie: userCookie } });
	assert.equal(response.status, 200);
	response = await fetch(`${baseUrl}/admin`, { headers: { Cookie: userCookie } });
	assert.equal(response.status, 200);
	assert.match(await response.text(), /admin-view/);
	response = await fetch(`${baseUrl}/admin/audit`, { headers: { Cookie: userCookie } });
	assert.equal(response.status, 200);
	assert.match(await response.text(), /audit-view/);
	response = await fetch(`${baseUrl}/api/admin/accounts`, { headers: { Cookie: userCookie } });
	const accounts = await response.json();
	assert.equal(accounts.accounts.length, 1);
	assert.equal(accounts.total, 1);
	assert.equal(accounts.accounts[0].role, 'admin');

	const secondPromotion = runPromotion('regular@example.com');
	assert.notEqual(secondPromotion.status, 0);

	response = await fetch(`${baseUrl}/api/register`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			displayName: 'Target User',
			email: 'target@example.com',
			password: 'target-account-password'
		})
	});
	assert.equal(response.status, 201);
	const targetRegistration = await response.json();
	const targetCookie = response.headers.get('set-cookie').split(';')[0];
	const targetId = targetRegistration.account.id;
	const database = new DatabaseSync(databaseFile);
	const adminHeaders = { Cookie: userCookie, 'Content-Type': 'application/json' };
	const regularHeaders = { Cookie: targetCookie, 'Content-Type': 'application/json' };

	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}/role`, {
		method: 'PATCH',
		headers: regularHeaders,
		body: JSON.stringify({ role: 'admin' })
	});
	assert.equal(response.status, 403);
	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}/status`, {
		method: 'PATCH',
		headers: regularHeaders,
		body: JSON.stringify({ status: 'suspended' })
	});
	assert.equal(response.status, 403);

	response = await fetch(`${baseUrl}/api/admin/accounts?q=target&limit=1&offset=0`, { headers: adminHeaders });
	assert.equal(response.status, 200);
	const searchResults = await response.json();
	assert.equal(searchResults.total, 1);
	assert.equal(searchResults.accounts[0].email, 'target@example.com');
	assert.equal(searchResults.accounts[0].status, 'active');
	assert.equal(searchResults.accounts[0].role, 'user');
	response = await fetch(`${baseUrl}/api/admin/accounts?limit=1&offset=0`, { headers: adminHeaders });
	const firstPage = await response.json();
	assert.equal(firstPage.accounts.length, 1);
	assert.equal(firstPage.total, 2);
	response = await fetch(`${baseUrl}/api/admin/accounts?limit=1&offset=1`, { headers: adminHeaders });
	const secondPage = await response.json();
	assert.equal(secondPage.accounts.length, 1);
	assert.notEqual(firstPage.accounts[0].id, secondPage.accounts[0].id);

	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}/role`, {
		method: 'PATCH',
		headers: adminHeaders,
		body: JSON.stringify({ role: 'admin' })
	});
	assert.equal(response.status, 200);
	assert.equal(database.prepare('SELECT role FROM accounts WHERE id = ?').get(targetId).role, 'admin');
	response = await fetch(`${baseUrl}/api/admin/audit-events?q=target%40example.com&limit=100`, { headers: adminHeaders });
	assert.equal(response.status, 200);
	const roleEvents = await response.json();
	const promotionEvent = roleEvents.events.find(event => event.action === 'role.changed' && event.affectedAccountId === targetId);
	assert.ok(promotionEvent);
	assert.equal(promotionEvent.actorAccountId, registration.account.id);
	assert.deepEqual(promotionEvent.metadata, { from: 'user', to: 'admin' });
	response = await fetch(`${baseUrl}/api/admin/audit-events?q=role.changed&limit=1`, { headers: adminHeaders });
	const auditPage = await response.json();
	assert.equal(auditPage.events.length, 1);
	assert.ok(auditPage.total >= 2);
	response = await fetch(`${baseUrl}/api/admin/audit-events`, {
		method: 'POST',
		headers: adminHeaders,
		body: '{}'
	});
	assert.equal(response.status, 404);

	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}/status`, {
		method: 'PATCH',
		headers: adminHeaders,
		body: JSON.stringify({ status: 'suspended' })
	});
	assert.equal(response.status, 200);
	assert.equal(database.prepare('SELECT status FROM accounts WHERE id = ?').get(targetId).status, 'suspended');
	assert.equal(database.prepare('SELECT COUNT(*) AS count FROM sessions WHERE account_id = ?').get(targetId).count, 0);
	assert.equal(database.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE affected_account_id = ? AND action = 'account.suspended'").get(targetId).count, 1);
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: targetCookie } });
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'target@example.com', password: 'target-account-password' })
	});
	assert.equal(response.status, 401);
	const suspendedLoginMessage = await response.json();
	assert.deepEqual(suspendedLoginMessage, { error: 'Email or password is incorrect.' });

	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}/status`, {
		method: 'PATCH',
		headers: adminHeaders,
		body: JSON.stringify({ status: 'active' })
	});
	assert.equal(response.status, 200);
	assert.equal(database.prepare('SELECT status FROM accounts WHERE id = ?').get(targetId).status, 'active');
	assert.equal(database.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE affected_account_id = ? AND action = 'account.reactivated'").get(targetId).count, 1);
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: targetCookie } });
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Forwarded-Proto': 'https' },
		body: JSON.stringify({ email: 'target@example.com', password: 'target-account-password' })
	});
	assert.equal(response.status, 200);
	assert.match(response.headers.get('set-cookie'), /; Secure/);
	const reactivatedCookie = response.headers.get('set-cookie').split(';')[0];
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: reactivatedCookie } });
	assert.equal(response.status, 200);

	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}/role`, {
		method: 'PATCH',
		headers: adminHeaders,
		body: JSON.stringify({ role: 'user' })
	});
	assert.equal(response.status, 200);
	assert.equal(database.prepare('SELECT role FROM accounts WHERE id = ?').get(targetId).role, 'user');

	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}/status`, {
		method: 'PATCH',
		headers: adminHeaders,
		body: JSON.stringify({ status: 'paused' })
	});
	assert.equal(response.status, 400);

	response = await fetch(`${baseUrl}/api/admin/accounts/${registration.account.id}/role`, {
		method: 'PATCH',
		headers: adminHeaders,
		body: JSON.stringify({ role: 'user' })
	});
	assert.equal(response.status, 409);
	response = await fetch(`${baseUrl}/api/admin/accounts/${registration.account.id}/status`, {
		method: 'PATCH',
		headers: adminHeaders,
		body: JSON.stringify({ status: 'suspended' })
	});
	assert.equal(response.status, 409);
	database.close();
});

test('audit events support filters and CSV export for admins', async () => {
	const auditDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'account-audit-'));
	const auditDatabaseFile = path.join(auditDirectory, 'audit.sqlite');
	const auditPort = await getFreePort();
	const auditUrl = `http://127.0.0.1:${auditPort}`;
	const auditServer = spawn(process.execPath, [serverFile], {
		stdio: 'ignore',
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(auditPort),
			APP_BASE_URL: 'https://accounts.example.test',
			DB_PATH: auditDatabaseFile,
			DB_BACKEND: 'sqlite',
			NODE_ENV: 'test',
			SMTP_HOST: '127.0.0.1',
			SMTP_PORT: String(smtpPort),
			MAIL_FROM: 'Account Desk <no-reply@example.test>',
			TRUST_PROXY: 'true'
		}
	});

	try {
		for (let attempt = 0; attempt < 50; attempt += 1) {
			if (auditServer.exitCode !== null) throw new Error('Audit test server exited before becoming ready.');
			try {
				const response = await fetch(`${auditUrl}/api/me`);
				if (response.status === 401) break;
			} catch {}
			await new Promise(resolve => setTimeout(resolve, 50));
		}

		let response = await fetch(`${auditUrl}/api/register`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				displayName: 'Audit User',
				email: 'audit-user@example.com',
				password: 'audit-user-password'
			})
		});
		assert.equal(response.status, 201);
		const created = await response.json();
		const sessionCookie = response.headers.get('set-cookie').split(';')[0];

		response = await fetch(`${auditUrl}/api/admin/audit-events?limit=20&offset=0&action=sign_in.succeeded&actorEmail=audit-user@example.com&affectedEmail=audit-user@example.com`, {
			headers: { Cookie: sessionCookie }
		});
		assert.equal(response.status, 403);

		const promotion = spawnSync(process.execPath, [serverFile, 'promote-admin', 'audit-user@example.com'], {
			encoding: 'utf8',
			env: { ...process.env, DB_BACKEND: 'sqlite', DB_PATH: auditDatabaseFile }
		});
		assert.equal(promotion.status, 0, promotion.stderr || promotion.stdout);
		const adminHeaders = { Cookie: sessionCookie, 'Content-Type': 'application/json' };
		response = await fetch(`${auditUrl}/api/login`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'audit-user@example.com', password: 'audit-user-password' })
		});
		assert.equal(response.status, 200);
		const loginCookie = response.headers.get('set-cookie').split(';')[0];
		const loggedInHeaders = { Cookie: loginCookie, 'Content-Type': 'application/json' };

		response = await fetch(`${auditUrl}/api/admin/audit-events?limit=20&offset=0&action=sign_in.succeeded&actorEmail=audit-user@example.com&affectedEmail=audit-user@example.com`, { headers: loggedInHeaders });
		assert.equal(response.status, 200);
		const filtered = await response.json();
		assert.ok(filtered.total >= 1);
		assert.ok(filtered.events.some(event => event.action === 'sign_in.succeeded' && event.actorEmail === 'audit-user@example.com'));

		response = await fetch(`${auditUrl}/api/admin/audit-events?format=csv&action=sign_in.succeeded&actorEmail=audit-user@example.com`, { headers: adminHeaders });
		assert.equal(response.status, 200);
		assert.match(response.headers.get('content-type'), /text\/csv/);
		const csvText = await response.text();
		assert.match(csvText, /event_id|actor_email|action|affected_email/i);
		assert.match(csvText, /sign_in\.succeeded/);
		assert.ok(!csvText.toLowerCase().includes('audit-user-password'));
		assert.ok(!csvText.includes('session='));

		response = await fetch(`${auditUrl}/api/admin/audit-events?from=2999-01-01T00:00:00.000Z&to=3000-01-01T00:00:00.000Z`, { headers: adminHeaders });
		assert.equal(response.status, 200);
		const dateFiltered = await response.json();
		assert.equal(dateFiltered.total, 0);
		assert.equal(dateFiltered.events.length, 0);
	} finally {
		if (auditServer.exitCode === null) {
			auditServer.kill('SIGTERM');
			await once(auditServer, 'exit');
		}
		await fs.rm(auditDirectory, { recursive: true, force: true });
	}
});

test('admin multi-factor authentication enforces validation at login', async () => {
	const mfaDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'account-mfa-'));
	const mfaDatabaseFile = path.join(mfaDirectory, 'mfa.sqlite');
	const mfaPort = await getFreePort();
	const mfaUrl = `http://127.0.0.1:${mfaPort}`;
	const mfaServer = spawn(process.execPath, [serverFile], {
		stdio: 'ignore',
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(mfaPort),
			APP_BASE_URL: 'https://accounts.example.test',
			DB_PATH: mfaDatabaseFile,
			DB_BACKEND: 'sqlite',
			NODE_ENV: 'test',
			SMTP_HOST: '127.0.0.1',
			SMTP_PORT: String(smtpPort),
			MAIL_FROM: 'Account Desk <no-reply@example.test>',
			TRUST_PROXY: 'true'
		}
	});

	try {
		for (let attempt = 0; attempt < 50; attempt += 1) {
			if (mfaServer.exitCode !== null) throw new Error('MFA test server exited before becoming ready.');
			try {
				const response = await fetch(`${mfaUrl}/api/me`);
				if (response.status === 401) break;
			} catch {}
			await new Promise(resolve => setTimeout(resolve, 50));
		}

		let response = await fetch(`${mfaUrl}/api/register`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				displayName: 'MFA Admin',
				email: 'mfa-admin@example.com',
				password: 'mfa-admin-password'
			})
		});
		assert.equal(response.status, 201);
		const cookie = response.headers.get('set-cookie').split(';')[0];
		const promotion = spawnSync(process.execPath, [serverFile, 'promote-admin', 'mfa-admin@example.com'], {
			encoding: 'utf8',
			env: { ...process.env, DB_BACKEND: 'sqlite', DB_PATH: mfaDatabaseFile }
		});
		assert.equal(promotion.status, 0, promotion.stderr || promotion.stdout);

		response = await fetch(`${mfaUrl}/api/me/mfa/setup`, {
			method: 'POST',
			headers: { Cookie: cookie }
		});
		assert.equal(response.status, 200);
		const setup = await response.json();
		assert.ok(setup.secret);
		assert.match(setup.otpauthUri, /^otpauth:\/\/totp\//);
		const code = totpCode(setup.secret);

		response = await fetch(`${mfaUrl}/api/me/mfa/enable`, {
			method: 'POST',
			headers: { Cookie: cookie, 'Content-Type': 'application/json' },
			body: JSON.stringify({ code })
		});
		assert.equal(response.status, 200);
		assert.equal((await response.json()).enabled, true);

		response = await fetch(`${mfaUrl}/api/login`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'mfa-admin@example.com', password: 'mfa-admin-password' })
		});
		assert.equal(response.status, 401);
		assert.match(JSON.stringify(await response.json()), /Multi-factor authentication/);

		response = await fetch(`${mfaUrl}/api/login`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'mfa-admin@example.com', password: 'mfa-admin-password', code })
		});
		assert.equal(response.status, 200);
		const adminCookie = response.headers.get('set-cookie').split(';')[0];

		response = await fetch(`${mfaUrl}/api/me/mfa`, {
			method: 'DELETE',
			headers: { Cookie: adminCookie, 'Content-Type': 'application/json' },
			body: JSON.stringify({ code })
		});
		assert.equal(response.status, 200);
		assert.equal((await response.json()).disabled, true);
	} finally {
		if (mfaServer.exitCode === null) {
			mfaServer.kill('SIGTERM');
			await once(mfaServer, 'exit');
		}
		await fs.rm(mfaDirectory, { recursive: true, force: true });
	}
});

test('admin detail endpoint exposes account context and recent activity', async () => {
	let response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			email: 'regular@example.com',
			password: 'regular-account-password'
		})
	});
	assert.equal(response.status, 200);
	const adminCookie = response.headers.get('set-cookie').split(';')[0];

	response = await fetch(`${baseUrl}/api/register`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			displayName: 'Detail Target',
			email: 'detail-target@example.com',
			password: 'detail-target-password'
		})
	});
	assert.equal(response.status, 201);
	const target = await response.json();
	const targetId = target.account.id;

	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'User-Agent': 'Detail Browser' },
		body: JSON.stringify({ email: 'detail-target@example.com', password: 'detail-target-password' })
	});
	assert.equal(response.status, 200);
	const targetCookie = response.headers.get('set-cookie').split(';')[0];

	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}`, { headers: { Cookie: adminCookie } });
	assert.equal(response.status, 200);
	const details = await response.json();
	assert.equal(details.account.email, 'detail-target@example.com');
	assert.equal(details.account.displayName, 'Detail Target');
	assert.ok(Array.isArray(details.recentAudit));
	assert.ok(Array.isArray(details.recentSessions));
	assert.ok(details.recentAudit.length >= 1 || details.recentSessions.length >= 1);

	response = await fetch(`${baseUrl}/api/admin/accounts/${targetId}`, { headers: { Cookie: targetCookie } });
	assert.equal(response.status, 403);
});

test('admin operational status panel exposes health without leaking secrets', async () => {
	let response = await fetch(`${baseUrl}/api/admin/status`, { headers: { Cookie: 'session=not-a-valid-session' } });
	assert.equal(response.status, 401);

	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'regular@example.com', password: 'regular-account-password' })
	});
	assert.equal(response.status, 200);
	const adminCookie = response.headers.get('set-cookie').split(';')[0];

	response = await fetch(`${baseUrl}/api/admin/status`, { headers: { Cookie: adminCookie } });
	assert.equal(response.status, 200);
	const status = await response.json();
	assert.ok(status.checkedAt);
	assert.ok(['healthy', 'degraded', 'unavailable'].includes(status.overall));
	assert.ok(status.database && typeof status.database.status === 'string');
	assert.ok(status.email && typeof status.email.status === 'string');
	assert.ok(status.backup && typeof status.backup.status === 'string');
	assert.equal(typeof status.database.backend, 'string');
	assert.equal(typeof status.email.configured, 'boolean');
	assert.equal(typeof status.backup.backend, 'string');
	assert.doesNotMatch(JSON.stringify(status), /DATABASE_URL|SMTP_PASS|smtp_pass|password/i);

	response = await fetch(`${baseUrl}/api/admin/status`, {
		headers: { Cookie: 'session=not-a-valid-session' }
	});
	assert.equal(response.status, 401);
});

test('admin invitation workflow creates accounts and rejects used or cancelled links', async () => {
	let response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'regular@example.com', password: 'regular-account-password' })
	});
	assert.equal(response.status, 200);
	const adminCookie = response.headers.get('set-cookie').split(';')[0];

	response = await fetch(`${baseUrl}/api/admin/invitations`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
		body: JSON.stringify({ email: 'invited@example.com' })
	});
	assert.equal(response.status, 200);
	let token = latestEmailToken('invite', 'invited@example.com');

	response = await fetch(`${baseUrl}/api/invitation/accept`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			token,
			displayName: 'Invited User',
			password: 'invited-account-password'
		})
	});
	const invitedResponseText = await response.text();
	assert.equal(response.status, 201, invitedResponseText);
	const invited = JSON.parse(invitedResponseText);
	assert.equal(invited.account.email, 'invited@example.com');
	assert.equal(invited.account.displayName, 'Invited User');
	assert.equal(invited.account.emailVerified, true);

	response = await fetch(`${baseUrl}/api/invitation/accept`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			token,
			displayName: 'Again',
			password: 'different-password'
		})
	});
	assert.equal(response.status, 409);

	response = await fetch(`${baseUrl}/api/admin/invitations`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
		body: JSON.stringify({ email: 'cancelled@example.com' })
	});
	assert.equal(response.status, 200);
	const cancelledToken = latestEmailToken('invite', 'cancelled@example.com');
	response = await fetch(`${baseUrl}/api/admin/invitations`, {
		method: 'DELETE',
		headers: { 'Content-Type': 'application/json', Cookie: adminCookie },
		body: JSON.stringify({ email: 'cancelled@example.com' })
	});
	assert.equal(response.status, 200);
	response = await fetch(`${baseUrl}/api/invitation/accept`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			token: cancelledToken,
			displayName: 'Cancelled User',
			password: 'cancelled-password'
		})
	});
	assert.equal(response.status, 410);
});

test('email verification and password management enforce one-time token rules', async () => {
	let response = await fetch(`${baseUrl}/api/register`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			displayName: 'Recovery User',
			email: 'recovery@example.com',
			password: 'original-account-password'
		})
	});
	assert.equal(response.status, 201);
	const registration = await response.json();
	const sessionCookie = response.headers.get('set-cookie').split(';')[0];
	assert.equal(registration.account.emailVerified, false);
	let token = latestEmailToken('verify_email', 'recovery@example.com');
	const database = new DatabaseSync(databaseFile);
	assert.ok(database.prepare('SELECT token_hash FROM account_tokens WHERE token_hash = ?')
		.get(createHash('sha256').update(token).digest('hex')));
	response = await fetch(`${baseUrl}/api/me/verification-email`, {
		method: 'POST',
		headers: { Cookie: sessionCookie }
	});
	assert.equal(response.status, 200);
	assert.match((await response.json()).message, /recovery@example\.com/);
	const originalToken = token;
	token = latestEmailToken('verify_email', 'recovery@example.com');
	assert.notEqual(token, originalToken);
	response = await fetch(`${baseUrl}/api/email/verify`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token: originalToken })
	});
	assert.equal(response.status, 400);

	response = await fetch(`${baseUrl}/api/email/verify`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token: 'not-a-valid-token' })
	});
	assert.equal(response.status, 400);
	response = await fetch(`${baseUrl}/api/email/verify`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token })
	});
	assert.equal(response.status, 200);
	assert.equal((await response.json()).account.emailVerified, true);
	response = await fetch(`${baseUrl}/api/email/verify`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token })
	});
	assert.equal(response.status, 409);

	response = await fetch(`${baseUrl}/api/me`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json', Cookie: sessionCookie },
		body: JSON.stringify({ displayName: 'Recovery User Updated', email: 'recovery-new@example.com' })
	});
	assert.equal(response.status, 200);
	const emailChange = await response.json();
	assert.equal(emailChange.account.email, 'recovery@example.com');
	assert.equal(emailChange.account.pendingEmail, 'recovery-new@example.com');
	token = latestEmailToken('verify_email', 'recovery-new@example.com');
	const accountId = registration.account.id;
	const accountRow = database.prepare('SELECT email, pending_email, email_verified_at FROM accounts WHERE id = ?').get(accountId);
	assert.equal(accountRow.email, 'recovery@example.com');
	assert.equal(accountRow.pending_email, 'recovery-new@example.com');
	const profileEvent = database.prepare("SELECT metadata_json FROM audit_events WHERE affected_account_id = ? AND action = 'profile.updated'").get(accountId);
	assert.deepEqual(JSON.parse(profileEvent.metadata_json), { changedFields: ['displayName', 'email'] });

	response = await fetch(`${baseUrl}/api/email/verify`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token })
	});
	assert.equal(response.status, 200);
	const verifiedChange = await response.json();
	assert.equal(verifiedChange.account.email, 'recovery-new@example.com');
	assert.equal(verifiedChange.account.pendingEmail, null);
	assert.equal(database.prepare('SELECT email_verified_at FROM accounts WHERE id = ?').get(accountId).email_verified_at !== null, true);

	response = await fetch(`${baseUrl}/api/me/password`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: sessionCookie },
		body: JSON.stringify({ currentPassword: 'wrong-current-password', newPassword: 'changed-account-password' })
	});
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'recovery-new@example.com', password: 'original-account-password' })
	});
	assert.equal(response.status, 200);
	const secondSessionCookie = response.headers.get('set-cookie').split(';')[0];
	response = await fetch(`${baseUrl}/api/me/password`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: sessionCookie },
		body: JSON.stringify({ currentPassword: 'original-account-password', newPassword: 'changed-account-password' })
	});
	assert.equal(response.status, 200);
	const rotatedCookie = response.headers.get('set-cookie').split(';')[0];
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: sessionCookie } });
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: secondSessionCookie } });
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: rotatedCookie } });
	assert.equal(response.status, 200);
	assert.equal(database.prepare('SELECT COUNT(*) AS count FROM sessions WHERE account_id = ?').get(accountId).count, 1);
	assert.equal(database.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE actor_account_id = ? AND action = 'sign_in.succeeded'").get(accountId).count >= 1, true);
	assert.equal(database.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE affected_account_id = ? AND action = 'password.changed'").get(accountId).count, 1);

	response = await fetch(`${baseUrl}/api/password-reset/request`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'nobody@example.com' })
	});
	assert.equal(response.status, 200);
	const unknownResetResponse = await response.json();
	const messagesBeforeReset = smtpMessages.length;
	response = await fetch(`${baseUrl}/api/password-reset/request`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'recovery-new@example.com' })
	});
	assert.equal(response.status, 200);
	assert.deepEqual(await response.json(), unknownResetResponse);
	assert.equal(smtpMessages.length, messagesBeforeReset + 1);
	token = latestEmailToken('password_reset', 'recovery-new@example.com');
	response = await fetch(`${baseUrl}/api/password-reset/complete`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token: 'invalid-reset-token', password: 'reset-account-password' })
	});
	assert.equal(response.status, 400);
	database.prepare('UPDATE account_tokens SET expires_at = ? WHERE token_hash = ?')
		.run(Date.now() - 1, createHash('sha256').update(token).digest('hex'));
	response = await fetch(`${baseUrl}/api/password-reset/complete`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token, password: 'reset-account-password' })
	});
	assert.equal(response.status, 410);

	response = await fetch(`${baseUrl}/api/password-reset/request`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'recovery-new@example.com' })
	});
	assert.equal(response.status, 200);
	token = latestEmailToken('password_reset', 'recovery-new@example.com');
	response = await fetch(`${baseUrl}/api/password-reset/complete`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token, password: 'reset-account-password' })
	});
	assert.equal(response.status, 200);
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: rotatedCookie } });
	assert.equal(response.status, 401);
	assert.equal(database.prepare('SELECT COUNT(*) AS count FROM sessions WHERE account_id = ?').get(accountId).count, 0);
	assert.equal(database.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE affected_account_id = ? AND action = 'password.reset'").get(accountId).count, 1);
	const auditMetadata = JSON.stringify(database.prepare('SELECT * FROM audit_events WHERE affected_account_id = ?').all(accountId));
	for (const secret of ['original-account-password', 'changed-account-password', 'reset-account-password', token]) {
		assert.equal(auditMetadata.includes(secret), false);
	}
	response = await fetch(`${baseUrl}/api/password-reset/complete`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token, password: 'another-reset-password' })
	});
	assert.equal(response.status, 409);

	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'recovery-new@example.com', password: 'reset-account-password' })
	});
	assert.equal(response.status, 200);
	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'missing@example.com', password: 'reset-account-password' })
	});
	assert.equal(response.status, 401);
	assert.deepEqual(await response.json(), { error: 'Email or password is incorrect.' });
	database.close();
});

test('sessions persist across restart, can be revoked, and expire', async () => {
	let response = await fetch(`${baseUrl}/sessions`);
	assert.equal(response.status, 401);
	response = await fetch(`${baseUrl}/api/me/sessions`);
	assert.equal(response.status, 401);

	response = await fetch(`${baseUrl}/api/register`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			displayName: 'Session User',
			email: 'sessions@example.com',
			password: 'session-account-password'
		})
	});
	assert.equal(response.status, 201);
	const account = (await response.json()).account;
	const firstCookie = response.headers.get('set-cookie').split(';')[0];
	response = await fetch(`${baseUrl}/sessions`, { headers: { Cookie: firstCookie } });
	assert.equal(response.status, 200);
	assert.match(await response.text(), /sessions-view/);

	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'User-Agent': 'Session Test Browser' },
		body: JSON.stringify({ email: 'sessions@example.com', password: 'session-account-password' })
	});
	assert.equal(response.status, 200);
	const secondCookie = response.headers.get('set-cookie').split(';')[0];
	const firstToken = firstCookie.slice('session='.length);
	const secondToken = secondCookie.slice('session='.length);
	let database = new DatabaseSync(databaseFile);
	assert.ok(database.prepare('SELECT session_id FROM sessions WHERE token_hash = ?')
		.get(createHash('sha256').update(firstToken).digest('hex')));
	assert.ok(database.prepare('SELECT session_id FROM sessions WHERE token_hash = ?')
		.get(createHash('sha256').update(secondToken).digest('hex')));
	database.close();

	response = await fetch(`${baseUrl}/api/me/sessions`, { headers: { Cookie: firstCookie } });
	assert.equal(response.status, 200);
	let activeSessions = (await response.json()).sessions;
	assert.equal(activeSessions.length, 2);
	assert.equal(activeSessions.filter(session => session.current).length, 1);
	const secondSession = activeSessions.find(session => !session.current);
	assert.ok(secondSession.userAgent.includes('Session Test Browser'));
	assert.ok(Date.parse(secondSession.expiresAt) > Date.now());
	response = await fetch(`${baseUrl}/api/register`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			displayName: 'Other User',
			email: 'other-session-user@example.com',
			password: 'other-session-password'
		})
	});
	assert.equal(response.status, 201);
	const otherAccount = (await response.json()).account;
	const otherCookie = response.headers.get('set-cookie').split(';')[0];
	response = await fetch(`${baseUrl}/api/me/sessions/${secondSession.id}`, {
		method: 'DELETE',
		headers: { Cookie: otherCookie }
	});
	assert.equal(response.status, 404);
	response = await fetch(`${baseUrl}/api/me`, {
		method: 'DELETE',
		headers: { 'Content-Type': 'application/json', Cookie: otherCookie },
		body: JSON.stringify({ password: 'other-session-password' })
	});
	assert.equal(response.status, 200);
	database = new DatabaseSync(databaseFile);
	const deletionEvent = database.prepare("SELECT * FROM audit_events WHERE affected_account_id = ? AND action = 'account.deleted'").get(otherAccount.id);
	assert.ok(deletionEvent);
	assert.equal(deletionEvent.actor_account_id, otherAccount.id);
	assert.equal(deletionEvent.affected_email, 'other-session-user@example.com');
	database.close();

	await stopAppServer();
	await startAppServer();
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: firstCookie } });
	assert.equal(response.status, 200);
	response = await fetch(`${baseUrl}/api/me/sessions`, { headers: { Cookie: firstCookie } });
	activeSessions = (await response.json()).sessions;
	assert.equal(activeSessions.length, 2);

	response = await fetch(`${baseUrl}/api/me/sessions/${secondSession.id}`, {
		method: 'DELETE',
		headers: { Cookie: firstCookie }
	});
	assert.equal(response.status, 200);
	assert.equal((await response.json()).current, false);
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: secondCookie } });
	assert.equal(response.status, 401);
	database = new DatabaseSync(databaseFile);
	assert.equal(database.prepare('SELECT COUNT(*) AS count FROM sessions WHERE account_id = ?').get(account.id).count, 1);
	database.close();

	response = await fetch(`${baseUrl}/api/logout`, {
		method: 'POST',
		headers: { Cookie: firstCookie, 'X-Forwarded-Proto': 'https' }
	});
	assert.equal(response.status, 200);
	assert.match(response.headers.get('set-cookie'), /HttpOnly/);
	assert.match(response.headers.get('set-cookie'), /SameSite=Strict/);
	assert.match(response.headers.get('set-cookie'), /; Secure/);
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: firstCookie } });
	assert.equal(response.status, 401);
	database = new DatabaseSync(databaseFile);
	assert.equal(database.prepare('SELECT COUNT(*) AS count FROM sessions WHERE account_id = ?').get(account.id).count, 0);
	database.close();

	response = await fetch(`${baseUrl}/api/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: 'sessions@example.com', password: 'session-account-password' })
	});
	const expiringCookie = response.headers.get('set-cookie').split(';')[0];
	const expiringToken = expiringCookie.slice('session='.length);
	database = new DatabaseSync(databaseFile);
	database.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?')
		.run(Date.now() - 1, createHash('sha256').update(expiringToken).digest('hex'));
	database.close();
	response = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: expiringCookie } });
	assert.equal(response.status, 401);
	database = new DatabaseSync(databaseFile);
	assert.equal(database.prepare('SELECT COUNT(*) AS count FROM sessions WHERE account_id = ?').get(account.id).count, 0);
	database.close();
});

test('registration, sign-in, and password-reset requests are rate limited', async () => {
	const rateDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'account-rate-limits-'));
	const rateDatabase = path.join(rateDirectory, 'accounts.sqlite');
	const ratePort = await getFreePort();
	const rateUrl = `http://127.0.0.1:${ratePort}`;
	const rateServer = spawn(process.execPath, [serverFile], {
		stdio: 'ignore',
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(ratePort),
			DB_BACKEND: 'sqlite',
			DB_PATH: rateDatabase,
			NODE_ENV: 'test',
			SMTP_HOST: '',
			RATE_LIMIT_WINDOW_MS: '60000',
			RATE_LIMIT_REGISTRATION_IP_MAX: '2',
			RATE_LIMIT_REGISTRATION_EMAIL_MAX: '100',
			RATE_LIMIT_SIGN_IN_IP_MAX: '5',
			RATE_LIMIT_SIGN_IN_EMAIL_MAX: '2',
			RATE_LIMIT_PASSWORD_RESET_IP_MAX: '5',
			RATE_LIMIT_PASSWORD_RESET_EMAIL_MAX: '2'
		}
	});

	try {
		let ready = false;
		for (let attempt = 0; attempt < 50; attempt += 1) {
			if (rateServer.exitCode !== null) throw new Error('Rate-limit test server exited before becoming ready.');
			try {
				const response = await fetch(`${rateUrl}/api/me`);
				if (response.status === 401) {
					ready = true;
					break;
				}
			} catch {}
			await new Promise(resolve => setTimeout(resolve, 50));
		}
		assert.equal(ready, true, 'Rate-limit test server should start');

		async function register(email, displayName) {
			return fetch(`${rateUrl}/api/register`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ displayName, email, password: 'valid-rate-limit-password' })
			});
		}

		let response = await register('rate-one@example.com', 'Rate One');
		assert.equal(response.status, 201);
		const cookie = response.headers.get('set-cookie');
		assert.match(cookie, /HttpOnly/);
		assert.match(cookie, /SameSite=Strict/);
		assert.doesNotMatch(cookie, /; Secure/);
		response = await register('rate-two@example.com', 'Rate Two');
		assert.equal(response.status, 201);
		response = await register('rate-three@example.com', 'Rate Three');
		assert.equal(response.status, 429);
		assert.ok(Number(response.headers.get('retry-after')) >= 1);

		const loginOptions = email => ({
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email, password: 'wrong-rate-limit-password' })
		});
		response = await fetch(`${rateUrl}/api/login`, loginOptions('rate-one@example.com'));
		assert.equal(response.status, 401);
		const invalidAccountMessage = await response.json();
		response = await fetch(`${rateUrl}/api/login`, loginOptions('rate-one@example.com'));
		assert.equal(response.status, 401);
		assert.deepEqual(await response.json(), invalidAccountMessage);
		response = await fetch(`${rateUrl}/api/login`, loginOptions('rate-one@example.com'));
		assert.equal(response.status, 429);
		response = await fetch(`${rateUrl}/api/login`, loginOptions('missing@example.com'));
		assert.equal(response.status, 401);
		assert.deepEqual(await response.json(), invalidAccountMessage);
		response = await fetch(`${rateUrl}/api/login`, loginOptions('rate-two@example.com'));
		assert.equal(response.status, 401);
		response = await fetch(`${rateUrl}/api/login`, loginOptions('another-missing@example.com'));
		assert.equal(response.status, 429);

		const database = new DatabaseSync(rateDatabase);
		database.prepare('UPDATE accounts SET email_verified_at = ? WHERE email = ?')
			.run(new Date().toISOString(), 'rate-one@example.com');
		database.close();
		response = await fetch(`${rateUrl}/api/password-reset/request`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'rate-one@example.com' })
		});
		assert.equal(response.status, 200);
		const existingAddressMessage = await response.json();
		response = await fetch(`${rateUrl}/api/password-reset/request`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'rate-one@example.com' })
		});
		assert.equal(response.status, 200);
		assert.deepEqual(await response.json(), existingAddressMessage);
		response = await fetch(`${rateUrl}/api/password-reset/request`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'rate-one@example.com' })
		});
		assert.equal(response.status, 429);
		response = await fetch(`${rateUrl}/api/password-reset/request`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'missing@example.com' })
		});
		assert.equal(response.status, 200);
		const missingAddressMessage = await response.json();
		assert.deepEqual(missingAddressMessage, existingAddressMessage);
		response = await fetch(`${rateUrl}/api/password-reset/request`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'another-missing@example.com' })
		});
		assert.equal(response.status, 200);
		assert.deepEqual(await response.json(), missingAddressMessage);
		response = await fetch(`${rateUrl}/api/password-reset/request`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'last-missing@example.com' })
		});
		assert.equal(response.status, 429);
		const rateDatabaseHandle = new DatabaseSync(rateDatabase);
		const rateBuckets = rateDatabaseHandle.prepare('SELECT bucket_hash FROM rate_limits').all();
		assert.ok(rateBuckets.length > 0);
		assert.ok(rateBuckets.every(bucket => /^[a-f0-9]{64}$/.test(bucket.bucket_hash)));
		rateDatabaseHandle.close();
	} finally {
		if (rateServer.exitCode === null) {
			rateServer.kill('SIGTERM');
			await once(rateServer, 'exit');
		}
		await fs.rm(rateDirectory, { recursive: true, force: true });
	}
});

test('SQLite backup restores to a new verified database without overwriting files', () => {
	const backupFile = path.join(temporaryDirectory, 'release-backup.sqlite');
	const restoredFile = path.join(temporaryDirectory, 'release-restored.sqlite');
	const env = { ...process.env, DB_BACKEND: 'sqlite', DB_PATH: databaseFile };
	const backupResult = spawnSync(process.execPath, [path.join(__dirname, 'db-tools.js'), 'backup', backupFile], {
		encoding: 'utf8',
		env
	});
	assert.equal(backupResult.status, 0, backupResult.stderr || backupResult.stdout);
	const backupStat = require('node:fs').statSync(backupFile);
	assert.equal(backupStat.mode & 0o777, 0o600);

	const restoreResult = spawnSync(process.execPath, [path.join(__dirname, 'db-tools.js'), 'restore', backupFile, restoredFile], {
		encoding: 'utf8',
		env
	});
	assert.equal(restoreResult.status, 0, restoreResult.stderr || restoreResult.stdout);
	const restored = new DatabaseSync(restoredFile, { readOnly: true });
	assert.equal(restored.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
	const sourceDatabase = new DatabaseSync(databaseFile, { readOnly: true });
	assert.equal(restored.prepare('SELECT COUNT(*) AS count FROM accounts').get().count,
		sourceDatabase.prepare('SELECT COUNT(*) AS count FROM accounts').get().count);
	sourceDatabase.close();
	assert.ok(restored.prepare('SELECT COUNT(*) AS count FROM audit_events').get().count > 0);
	restored.close();

	const overwriteResult = spawnSync(process.execPath, [path.join(__dirname, 'db-tools.js'), 'backup', backupFile], {
		encoding: 'utf8',
		env
	});
	assert.notEqual(overwriteResult.status, 0);
});

test('production startup rejects insecure or incomplete deployment settings', () => {
	const result = spawnSync(process.execPath, [serverFile], {
		encoding: 'utf8',
		env: {
			...process.env,
			NODE_ENV: 'production',
			APP_BASE_URL: 'http://accounts.example.test',
			TRUST_PROXY: 'true',
			SMTP_HOST: 'smtp.example.test',
			MAIL_FROM: 'Account Desk <no-reply@example.test>',
			DB_PATH: path.join(temporaryDirectory, 'invalid-production.sqlite')
		}
	});
	assert.notEqual(result.status, 0);
	assert.match(`${result.stdout}${result.stderr}`, /APP_BASE_URL to use HTTPS/);

	const missingDatabase = spawnSync(process.execPath, [serverFile], {
		encoding: 'utf8',
		env: {
			...process.env,
			NODE_ENV: 'production',
			APP_BASE_URL: 'https://accounts.example.test',
			TRUST_PROXY: 'true',
			SMTP_HOST: 'smtp.example.test',
			MAIL_FROM: 'Account Desk <no-reply@example.test>',
			DB_BACKEND: 'postgres',
			DATABASE_URL: '',
			DB_PATH: path.join(temporaryDirectory, 'missing-production.sqlite')
		}
	});
	assert.notEqual(missingDatabase.status, 0);
	assert.match(`${missingDatabase.stdout}${missingDatabase.stderr}`, /DATABASE_URL for Supabase Postgres/);

	const missingCertificate = spawnSync(process.execPath, [serverFile], {
		encoding: 'utf8',
		env: {
			...process.env,
			NODE_ENV: 'production',
			APP_BASE_URL: 'https://accounts.example.test',
			TRUST_PROXY: 'true',
			SMTP_HOST: 'smtp.example.test',
			MAIL_FROM: 'Account Desk <no-reply@example.test>',
			DB_BACKEND: 'postgres',
			DATABASE_URL: 'postgresql://postgres:placeholder@pooler.example.test:5432/postgres',
			DATABASE_SSL_CA: '',
			DB_PATH: path.join(temporaryDirectory, 'missing-ca-production.sqlite')
		}
	});
	assert.notEqual(missingCertificate.status, 0);
	assert.match(`${missingCertificate.stdout}${missingCertificate.stderr}`, /DATABASE_SSL_CA to verify/);
});

test('Supabase tooling requires a private connection URL and refuses SQLite backup mode', () => {
	const toolsFile = path.join(__dirname, 'db-tools.js');
	const missingUrl = spawnSync(process.execPath, [toolsFile, 'migrate-supabase'], {
		encoding: 'utf8',
		env: { ...process.env, DB_BACKEND: 'postgres', DATABASE_URL: '' }
	});
	assert.notEqual(missingUrl.status, 0);
	assert.match(`${missingUrl.stdout}${missingUrl.stderr}`, /Set DATABASE_URL in \.env/);

	const wrongBackupMode = spawnSync(process.execPath, [toolsFile, 'backup', path.join(temporaryDirectory, 'should-not-be-created.sqlite')], {
		encoding: 'utf8',
		env: { ...process.env, DB_BACKEND: 'postgres', DATABASE_URL: 'postgresql://not-used' }
	});
	assert.notEqual(wrongBackupMode.status, 0);
	assert.match(`${wrongBackupMode.stdout}${wrongBackupMode.stderr}`, /manage SQLite only/);
});