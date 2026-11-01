class SupabaseAuthError extends Error {
	constructor(status, code, message) {
		super(message || 'Supabase Auth request failed.');
		this.name = 'SupabaseAuthError';
		this.status = status;
		this.code = code;
	}
}

function createSupabaseAuth({ url, anonKey, serviceRoleKey, fetchImpl = fetch }) {
	const baseUrl = url?.replace(/\/+$/, '');

	async function request(path, { method = 'GET', body, accessToken, admin = false } = {}) {
		const apiKey = admin ? serviceRoleKey : anonKey;
		if (!baseUrl || !apiKey) throw new Error('Supabase Auth is not configured.');
		const headers = { apikey: apiKey, Authorization: `Bearer ${accessToken || apiKey}` };
		if (body !== undefined) headers['Content-Type'] = 'application/json';
		const response = await fetchImpl(`${baseUrl}/auth/v1${path}`, {
			method,
			headers,
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		});
		let result = {};
		try {
			result = await response.json();
		} catch {}
		if (!response.ok) {
			throw new SupabaseAuthError(response.status, result.code || result.error_code || result.error, result.msg || result.message || result.error_description);
		}
		return result;
	}

	const redirectPath = (path, redirectTo) => `${path}?redirect_to=${encodeURIComponent(redirectTo)}`;

	return {
		signUp: (email, password, displayName, redirectTo) => request(redirectPath('/signup', redirectTo), {
			method: 'POST',
			body: { email, password, data: { display_name: displayName } }
		}),
		signInWithPassword: (email, password) => request('/token?grant_type=password', {
			method: 'POST',
			body: { email, password }
		}),
		getUser: accessToken => request('/user', { accessToken }),
		refreshSession: refreshToken => request('/token?grant_type=refresh_token', {
			method: 'POST',
			body: { refresh_token: refreshToken }
		}),
		setPassword: (accessToken, password) => request('/user', {
			method: 'PUT',
			accessToken,
			body: { password }
		}),
		updateEmail: (accessToken, email) => request('/user', {
			method: 'PUT',
			accessToken,
			body: { email }
		}),
		requestPasswordReset: (email, redirectTo) => request(redirectPath('/recover', redirectTo), {
			method: 'POST',
			body: { email }
		}),
		resendConfirmation: (email, redirectTo, type = 'signup') => request(redirectPath('/resend', redirectTo), {
			method: 'POST',
			body: { type, email }
		}),
		logout: accessToken => request('/logout', { method: 'POST', accessToken }),
		verifyAccessToken: accessToken => request('/user', { accessToken }),
		inviteUser: (email, displayName, redirectTo) => request(redirectPath('/invite', redirectTo), {
			method: 'POST',
			admin: true,
			body: { email, data: { display_name: displayName } }
		}),
		getAdminUser: userId => request(`/admin/users/${encodeURIComponent(userId)}`, { admin: true }),
		setAccountId: async (userId, accountId) => {
			const { user } = await request(`/admin/users/${encodeURIComponent(userId)}`, { admin: true });
			return request(`/admin/users/${encodeURIComponent(userId)}`, {
				method: 'PUT',
				admin: true,
				body: { app_metadata: { ...(user.app_metadata || {}), account_id: accountId } }
			});
		},
		listUsers: (page = 1, perPage = 1000) => request(`/admin/users?page=${page}&per_page=${perPage}`, { admin: true }),
		findUserByEmail: async email => {
			for (let page = 1; page <= 1000; page += 1) {
				const result = await request(`/admin/users?page=${page}&per_page=1000`, { admin: true });
				const user = (result.users || []).find(item => item.email?.toLowerCase() === email.toLowerCase());
				if (user) return user;
				if ((result.users || []).length < 1000) return null;
			}
			throw new Error('Supabase Auth user pagination exceeded the supported limit.');
		},
		deleteUser: userId => request(`/admin/users/${encodeURIComponent(userId)}`, { method: 'DELETE', admin: true })
	};
}

module.exports = { createSupabaseAuth, SupabaseAuthError };