const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createSupabaseAuth, SupabaseAuthError } = require('./supabase-auth');

function createResponse(status, value) {
	return {
		ok: status >= 200 && status < 300,
		status,
		json: async () => value
	};
}

test('Supabase password sign-in uses the public key and sends credentials to Auth', async () => {
	let request;
	const auth = createSupabaseAuth({
		url: 'https://project.example/',
		anonKey: 'public-key',
		serviceRoleKey: 'server-only-key',
		fetchImpl: async (url, options) => {
			request = { url, options };
			return createResponse(200, { access_token: 'access', refresh_token: 'refresh' });
		}
	});

	const result = await auth.signInWithPassword('person@example.com', 'correct-password');
	assert.equal(request.url, 'https://project.example/auth/v1/token?grant_type=password');
	assert.equal(request.options.headers.apikey, 'public-key');
	assert.equal(request.options.headers.Authorization, 'Bearer public-key');
	assert.deepEqual(JSON.parse(request.options.body), { email: 'person@example.com', password: 'correct-password' });
	assert.equal(result.refresh_token, 'refresh');
});

test('Supabase admin account metadata updates keep server credentials server-side', async () => {
	const requests = [];
	const auth = createSupabaseAuth({
		url: 'https://project.example',
		anonKey: 'public-key',
		serviceRoleKey: 'server-only-key',
		fetchImpl: async (url, options) => {
			requests.push({ url, options });
			return createResponse(200, url.endsWith('/auth/v1/admin/users/user-id')
				? { user: { app_metadata: { provider: 'email' } } }
				: { user: { id: 'user-id' } });
		}
	});

	await auth.setAccountId('user-id', 'account-id');
	assert.equal(requests.length, 2);
	assert.ok(requests.every(({ options }) => options.headers.apikey === 'server-only-key'));
	assert.deepEqual(JSON.parse(requests[1].options.body), {
		app_metadata: { provider: 'email', account_id: 'account-id' }
	});
});

test('Supabase Auth errors preserve status and machine-readable code', async () => {
	const auth = createSupabaseAuth({
		url: 'https://project.example',
		anonKey: 'public-key',
		serviceRoleKey: 'server-only-key',
		fetchImpl: async () => createResponse(400, { code: 'email_not_confirmed', msg: 'Email not confirmed' })
	});

	await assert.rejects(auth.getUser('bad-token'), error => {
		assert.ok(error instanceof SupabaseAuthError);
		assert.equal(error.status, 400);
		assert.equal(error.code, 'email_not_confirmed');
		return true;
	});
});