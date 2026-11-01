const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const fs = require("node:fs/promises");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { test } = require("node:test");

const serverFile = path.join(__dirname, "server.js");

async function getFreePort() {
  const probe = net.createServer();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((resolve, reject) =>
    probe.close((error) => (error ? reject(error) : resolve())),
  );
  return port;
}

function runCommand(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
    child.once("error", reject);
    child.once("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("Supabase Auth server flow registers, verifies, signs in, and signs out", async () => {
  const temporaryDirectory = await fs.mkdtemp(
    path.join(os.tmpdir(), "supabase-auth-flow-"),
  );
  const databaseFile = path.join(temporaryDirectory, "accounts.sqlite");
  const authPort = await getFreePort();
  const appPort = await getFreePort();
  const usersById = new Map();
  const usersByEmail = new Map();
  const accessUsers = new Map();
  const refreshUsers = new Map();
  const resendTypes = [];
  let tokenNumber = 0;
  const makeSession = (user) => {
    tokenNumber += 1;
    const access_token = `access-${tokenNumber}`;
    const refresh_token = `refresh-${tokenNumber}`;
    accessUsers.set(access_token, user);
    refreshUsers.set(refresh_token, user);
    return { access_token, refresh_token, expires_in: 3600, user };
  };
  const authServer = http.createServer(async (request, response) => {
    const url = new URL(request.url, "http://localhost");
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = chunks.length
      ? JSON.parse(Buffer.concat(chunks).toString("utf8"))
      : {};
    const reply = (status, value) => {
      response.writeHead(status, { "Content-Type": "application/json" });
      response.end(JSON.stringify(value));
    };
    const addUser = (email, password, metadata = {}) => {
      const user = {
        id: `auth-user-${usersById.size + 1}`,
        email,
        email_confirmed_at: null,
        app_metadata: { provider: "email", providers: ["email"] },
        user_metadata: metadata,
      };
      usersById.set(user.id, user);
      usersByEmail.set(user.email, { user, password });
      return user;
    };

    if (url.pathname === "/auth/v1/signup" && request.method === "POST") {
      const user = addUser(body.email, body.password, body.data || {});
      return reply(200, { user });
    }

    if (url.pathname === "/auth/v1/invite" && request.method === "POST") {
      if (request.headers.apikey !== "server-only-key")
        return reply(401, { message: "Unauthorized" });
      const user = addUser(body.email, "", body.data || {});
      return reply(200, { user });
    }

    if (url.pathname === "/auth/v1/admin/users" && request.method === "GET") {
      if (request.headers.apikey !== "server-only-key")
        return reply(401, { message: "Unauthorized" });
      return reply(200, { users: [...usersById.values()] });
    }

    if (url.pathname.startsWith("/auth/v1/admin/users/")) {
      if (request.headers.apikey !== "server-only-key")
        return reply(401, { message: "Unauthorized" });
      const userId = decodeURIComponent(url.pathname.split("/").pop());
      const user = usersById.get(userId);
      if (!user) return reply(404, { message: "User not found" });
      if (request.method === "GET") return reply(200, { user });
      if (request.method === "DELETE") {
        usersById.delete(userId);
        usersByEmail.delete(user.email);
        return reply(200, {});
      }
      if (request.method === "PUT") {
        if (body.app_metadata) user.app_metadata = body.app_metadata;
        return reply(200, { user });
      }
    }

    if (
      url.pathname === "/auth/v1/token" &&
      url.searchParams.get("grant_type") === "password"
    ) {
      const record = usersByEmail.get(body.email);
      if (!record || record.password !== body.password)
        return reply(400, {
          code: "invalid_credentials",
          msg: "Invalid credentials",
        });
      if (!record.user.email_confirmed_at)
        return reply(400, {
          code: "email_not_confirmed",
          msg: "Email not confirmed",
        });
      return reply(200, makeSession(record.user));
    }

    if (
      url.pathname === "/auth/v1/token" &&
      url.searchParams.get("grant_type") === "refresh_token"
    ) {
      const user = refreshUsers.get(body.refresh_token);
      return user
        ? reply(200, makeSession(user))
        : reply(400, { code: "invalid_grant", msg: "Refresh token invalid" });
    }

    if (url.pathname === "/auth/v1/user" && request.method === "GET") {
      const token = request.headers.authorization?.replace(/^Bearer\s+/i, "");
      const user = accessUsers.get(token);
      return user
        ? reply(200, user)
        : reply(401, { code: "invalid_token", msg: "Invalid token" });
    }

    if (url.pathname === "/auth/v1/user" && request.method === "PUT") {
      const token = request.headers.authorization?.replace(/^Bearer\s+/i, "");
      const user = accessUsers.get(token);
      if (!user)
        return reply(401, { code: "invalid_token", msg: "Invalid token" });
      const record = usersByEmail.get(user.email);
      if (body.password !== undefined) record.password = body.password;
      if (body.email !== undefined) user.pending_email = body.email;
      return reply(200, { user });
    }

    if (
      url.pathname === "/auth/v1/recover" ||
      url.pathname === "/auth/v1/resend"
    ) {
      if (url.pathname.endsWith("/resend")) resendTypes.push(body.type);
      return reply(200, {});
    }
    if (url.pathname === "/auth/v1/logout") return reply(204, {});
    return reply(404, { message: "Not found" });
  });
  authServer.listen(authPort, "127.0.0.1");
  await once(authServer, "listening");

  const appProcess = spawn(process.execPath, [serverFile], {
    stdio: "ignore",
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(appPort),
      APP_BASE_URL: "https://accounts.example.test",
      DB_BACKEND: "sqlite",
      DB_PATH: path.join(temporaryDirectory, "accounts.sqlite"),
      NODE_ENV: "test",
      AUTH_BACKEND: "supabase",
      SUPABASE_URL: `http://127.0.0.1:${authPort}`,
      SUPABASE_ANON_KEY: "public-key",
      SUPABASE_SERVICE_ROLE_KEY: "server-only-key",
    },
  });
  const baseUrl = `http://127.0.0.1:${appPort}`;

  try {
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      if (appProcess.exitCode !== null)
        throw new Error("Supabase Auth test app exited before becoming ready.");
      try {
        const response = await fetch(`${baseUrl}/api/me`);
        if (response.status === 401) {
          ready = true;
          break;
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(ready, true, "Supabase Auth test app should start");

    let response = await fetch(`${baseUrl}/api/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        displayName: "Supabase User",
        email: "supabase-user@example.com",
        password: "valid-supabase-password",
      }),
    });
    assert.equal(response.status, 201);
    const registration = await response.json();
    assert.equal(registration.needsEmailVerification, true);
    const user = usersByEmail.get("supabase-user@example.com").user;
    assert.equal(user.app_metadata.account_id, registration.account.id);

    user.email_confirmed_at = new Date().toISOString();
    const linkSession = makeSession(user);
    response = await fetch(`${baseUrl}/api/auth/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        access_token: linkSession.access_token,
        refresh_token: linkSession.refresh_token,
        type: "signup",
      }),
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).account.emailVerified, true);
    let cookies = response.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";")[0])
      .join("; ");
    const database = new DatabaseSync(databaseFile);
    database
      .prepare("UPDATE accounts SET role = 'admin' WHERE id = ?")
      .run(registration.account.id);
    database.close();

    response = await fetch(`${baseUrl}/api/me`, {
      headers: { Cookie: cookies },
    });
    assert.equal(response.status, 200);
    assert.equal(
      (await response.json()).account.email,
      "supabase-user@example.com",
    );

    response = await fetch(`${baseUrl}/api/password-reset/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "supabase-user@example.com" }),
    });
    assert.equal(response.status, 200);

    response = await fetch(`${baseUrl}/api/me`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: cookies },
      body: JSON.stringify({
        displayName: "Supabase User",
        email: "supabase-new@example.com",
      }),
    });
    assert.equal(response.status, 200);
    assert.equal(
      (await response.json()).account.pendingEmail,
      "supabase-new@example.com",
    );
    response = await fetch(`${baseUrl}/api/me/verification-email`, {
      method: "POST",
      headers: { Cookie: cookies },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(resendTypes, ["email_change"]);

    const existingAuthRecord = usersByEmail.get("supabase-user@example.com");
    usersByEmail.delete("supabase-user@example.com");
    user.email = "supabase-new@example.com";
    user.email_confirmed_at = new Date().toISOString();
    usersByEmail.set(user.email, existingAuthRecord);
    const emailChangeSession = makeSession(user);
    response = await fetch(`${baseUrl}/api/auth/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        access_token: emailChangeSession.access_token,
        refresh_token: emailChangeSession.refresh_token,
        type: "email_change",
      }),
    });
    assert.equal(response.status, 200);
    assert.equal(
      (await response.json()).account.email,
      "supabase-new@example.com",
    );
    cookies = response.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";")[0])
      .join("; ");

    response = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "supabase-new@example.com",
        password: "valid-supabase-password",
      }),
    });
    assert.equal(response.status, 200);
    cookies = response.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";")[0])
      .join("; ");

    response = await fetch(`${baseUrl}/api/me/password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookies },
      body: JSON.stringify({
        currentPassword: "valid-supabase-password",
        newPassword: "changed-supabase-password",
      }),
    });
    assert.equal(response.status, 200);
    cookies = response.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";")[0])
      .join("; ");
    const adminCookies = cookies;

    response = await fetch(`${baseUrl}/api/admin/status`, {
      headers: { Cookie: adminCookies },
    });
    assert.equal(response.status, 200);
    const operationalStatus = await response.json();
    assert.equal(operationalStatus.email.configured, true);
    assert.equal(operationalStatus.email.status, "healthy");
    assert.match(operationalStatus.email.summary, /Supabase Auth/);

    response = await fetch(`${baseUrl}/api/admin/invitations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookies },
      body: JSON.stringify({ email: "invited-supabase@example.com" }),
    });
    assert.equal(response.status, 200);
    const invitedUser = usersByEmail.get("invited-supabase@example.com").user;
    assert.ok(invitedUser.app_metadata.account_id);
    invitedUser.email_confirmed_at = new Date().toISOString();
    const inviteSession = makeSession(invitedUser);
    const mismatchedSession = makeSession(user);
    response = await fetch(`${baseUrl}/api/auth/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        access_token: mismatchedSession.access_token,
        refresh_token: inviteSession.refresh_token,
        type: "invite",
      }),
    });
    assert.equal(response.status, 400);
    response = await fetch(`${baseUrl}/api/auth/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        access_token: inviteSession.access_token,
        refresh_token: inviteSession.refresh_token,
        type: "invite",
      }),
    });
    assert.equal(response.status, 200);
    cookies = response.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";")[0])
      .join("; ");
    response = await fetch(`${baseUrl}/api/invitation/accept`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookies },
      body: JSON.stringify({
        displayName: "Invited Supabase User",
        password: "new-invited-password",
      }),
    });
    assert.equal(response.status, 201);
    assert.equal(
      (await response.json()).account.displayName,
      "Invited Supabase User",
    );

    response = await fetch(`${baseUrl}/api/admin/invitations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: adminCookies },
      body: JSON.stringify({ email: "cancelled-supabase@example.com" }),
    });
    assert.equal(response.status, 200);
    response = await fetch(`${baseUrl}/api/admin/invitations`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Cookie: adminCookies },
      body: JSON.stringify({ email: "cancelled-supabase@example.com" }),
    });
    assert.equal(response.status, 200);
    assert.equal(usersByEmail.has("cancelled-supabase@example.com"), false);

    const legacyAccountId = "legacy-account-001";
    const migrationDatabase = new DatabaseSync(databaseFile);
    migrationDatabase
      .prepare(
        `
			INSERT INTO accounts (id, email, display_name, created_at, role, status, salt, password_hash)
			VALUES (?, ?, ?, ?, 'user', 'active', ?, ?)
		`,
      )
      .run(
        legacyAccountId,
        "legacy-supabase@example.com",
        "Legacy User",
        new Date().toISOString(),
        "legacy-salt",
        "legacy-hash",
      );
    migrationDatabase
      .prepare(
        "INSERT INTO sessions (session_id, token_hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run("legacy-session", "a".repeat(64), legacyAccountId, Date.now(), Date.now() + 3600000);
    migrationDatabase
      .prepare(
        "INSERT INTO account_tokens (token_hash, account_id, purpose, email, expires_at) VALUES (?, ?, 'verify_email', ?, ?)",
      )
      .run("b".repeat(64), legacyAccountId, "legacy-supabase@example.com", Date.now() + 3600000);
    migrationDatabase.close();
    const migrationEnv = {
      ...process.env,
      DB_BACKEND: "sqlite",
      DB_PATH: databaseFile,
      AUTH_BACKEND: "supabase",
      SUPABASE_URL: `http://127.0.0.1:${authPort}`,
      SUPABASE_ANON_KEY: "public-key",
      SUPABASE_SERVICE_ROLE_KEY: "server-only-key",
      APP_BASE_URL: "https://accounts.example.test",
    };
    const dryRun = await runCommand([serverFile, "migrate-auth"], migrationEnv);
    assert.equal(dryRun.status, 0, dryRun.stderr || dryRun.stdout);
    assert.match(dryRun.stdout, /Dry run: 1 account/);
    assert.equal(usersByEmail.has("legacy-supabase@example.com"), false);

    const migration = await runCommand(
      [serverFile, "migrate-auth", "--apply"],
      migrationEnv,
    );
    assert.equal(migration.status, 0, migration.stderr || migration.stdout);
    assert.match(migration.stdout, /Migrated 1 account/);
    const migratedUser = usersByEmail.get("legacy-supabase@example.com").user;
    assert.equal(migratedUser.app_metadata.account_id, legacyAccountId);
    const verifyMigration = new DatabaseSync(databaseFile);
    const migratedProfile = verifyMigration
      .prepare("SELECT salt, password_hash FROM accounts WHERE id = ?")
      .get(legacyAccountId);
    assert.equal(migratedProfile.salt, "");
    assert.equal(migratedProfile.password_hash, "");
    assert.equal(
      verifyMigration
        .prepare("SELECT COUNT(*) AS count FROM sessions WHERE account_id = ?")
        .get(legacyAccountId).count,
      0,
    );
    assert.equal(
      verifyMigration
        .prepare(
          "SELECT COUNT(*) AS count FROM account_tokens WHERE account_id = ? AND purpose IN ('verify_email', 'password_reset')",
        )
        .get(legacyAccountId).count,
      0,
    );
    assert.ok(
      verifyMigration
        .prepare(
          "SELECT token_hash FROM account_tokens WHERE account_id = ? AND purpose = 'invite'",
        )
        .get(legacyAccountId),
    );
    verifyMigration.close();

    response = await fetch(`${baseUrl}/api/logout`, {
      method: "POST",
      headers: { Cookie: cookies },
    });
    assert.equal(response.status, 200);
    response = await fetch(`${baseUrl}/api/me`, {
      headers: { Cookie: cookies },
    });
    assert.equal(response.status, 401);
  } finally {
    if (appProcess.exitCode === null) {
      appProcess.kill("SIGTERM");
      await once(appProcess, "exit");
    }
    authServer.close();
    await once(authServer, "close");
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  }
});
