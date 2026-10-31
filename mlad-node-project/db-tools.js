const { DatabaseSync, backup } = require('node:sqlite');
const { Pool } = require('pg');
const fs = require('node:fs/promises');
const path = require('node:path');
require('dotenv').config();

const root = __dirname;
const databaseFile = path.resolve(process.env.DB_PATH || path.join(root, 'data', 'accounts.sqlite'));

async function postgresPoolOptions() {
	if (!process.env.DATABASE_URL) throw new Error('Set DATABASE_URL in .env before using Supabase.');
	if (!process.env.DATABASE_SSL_CA) throw new Error('Set DATABASE_SSL_CA to the Supabase root certificate file.');
	const connectionString = new URL(process.env.DATABASE_URL);
	for (const option of ['sslmode', 'sslcert', 'sslkey', 'sslrootcert']) connectionString.searchParams.delete(option);
	return {
		connectionString: connectionString.toString(),
		ssl: {
			rejectUnauthorized: true,
			ca: await fs.readFile(path.resolve(root, process.env.DATABASE_SSL_CA), 'utf8')
		}
	};
}

async function assertDestinationIsNew(destination) {
	if (path.resolve(destination) === databaseFile) {
		throw new Error('Backup/restore destination must not be the configured live database path.');
	}
	try {
		await fs.access(destination);
		throw new Error(`Destination already exists: ${destination}`);
	} catch (error) {
		if (error.code !== 'ENOENT') throw error;
	}
	await fs.mkdir(path.dirname(destination), { recursive: true });
}

function verifyDatabase(file) {
	const database = new DatabaseSync(file, { readOnly: true });
	try {
		const result = database.prepare('PRAGMA integrity_check').get();
		if (result.integrity_check !== 'ok') throw new Error(`SQLite integrity check failed for ${file}.`);
		const hasAccounts = database.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'accounts'").get();
		if (!hasAccounts) throw new Error(`No accounts table found in ${file}.`);
	} finally {
		database.close();
	}
}

async function copyDatabase(sourceFile, destinationFile) {
	const resolvedSource = path.resolve(sourceFile);
	const resolvedDestination = path.resolve(destinationFile);
	if (resolvedSource === resolvedDestination) throw new Error('Source and destination must be different files.');
	verifyDatabase(resolvedSource);
	await assertDestinationIsNew(resolvedDestination);
	const source = new DatabaseSync(resolvedSource, { readOnly: true });
	try {
		await backup(source, resolvedDestination);
	} finally {
		source.close();
	}
	await fs.chmod(resolvedDestination, 0o600);
	verifyDatabase(resolvedDestination);
}

async function migrateSqliteToSupabase(sourceFile) {
	const sourcePath = path.resolve(sourceFile);
	verifyDatabase(sourcePath);
	const source = new DatabaseSync(sourcePath, { readOnly: true });
	const poolOptions = await postgresPoolOptions();
	const pool = new Pool({
		...poolOptions,
		max: 2,
		connectionTimeoutMillis: 10000
	});
	const tables = [
		['accounts', ['id', 'email', 'display_name', 'created_at', 'role', 'status', 'email_verified_at', 'pending_email', 'salt', 'password_hash']],
		['account_tokens', ['token_hash', 'account_id', 'purpose', 'email', 'expires_at', 'used_at']],
		['sessions', ['session_id', 'token_hash', 'account_id', 'created_at', 'expires_at', 'user_agent']],
		['audit_events', ['event_id', 'actor_account_id', 'actor_email', 'action', 'affected_account_id', 'affected_email', 'occurred_at', 'metadata_json']],
		['rate_limits', ['bucket_hash', 'window_started_at', 'attempts', 'expires_at']]
	];

	try {
		const schema = await fs.readFile(path.join(root, 'supabase', 'migrations', '20261031_initial_schema.sql'), 'utf8');
		await pool.query('SELECT 1');
		await pool.query(schema);
		const existing = await pool.query(`
			SELECT
				(SELECT COUNT(*) FROM accounts) AS accounts,
				(SELECT COUNT(*) FROM account_tokens) AS tokens,
				(SELECT COUNT(*) FROM sessions) AS sessions,
				(SELECT COUNT(*) FROM audit_events) AS audit_events,
				(SELECT COUNT(*) FROM rate_limits) AS rate_limits
		`);
		if (Object.values(existing.rows[0]).some(value => Number(value) > 0)) {
			throw new Error('Supabase tables are not empty. Refusing to merge SQLite data into an initialized database.');
		}

		const client = await pool.connect();
		try {
			await client.query('BEGIN');
			for (const [table, columns] of tables) {
				const rows = source.prepare(`SELECT ${columns.join(', ')} FROM ${table}`).all();
				if (rows.length === 0) continue;
				const placeholders = columns.map((_, index) => `$${index + 1}`).join(', ');
				const insert = `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`;
				for (const row of rows) await client.query(insert, columns.map(column => row[column] ?? null));
			}
			await client.query(`
				SELECT setval(
					pg_get_serial_sequence('audit_events', 'event_id'),
					COALESCE((SELECT MAX(event_id) FROM audit_events), 1),
					EXISTS(SELECT 1 FROM audit_events)
				)
			`);
			await client.query('COMMIT');
		} catch (error) {
			await client.query('ROLLBACK');
			throw error;
		} finally {
			client.release();
		}
		console.log(`Imported ${source.prepare('SELECT COUNT(*) AS count FROM accounts').get().count} accounts and related data into Supabase.`);
	} finally {
		source.close();
		await pool.end();
	}
}

async function main() {
	const [command, firstPath, secondPath] = process.argv.slice(2);
	if (['backup', 'restore'].includes(command)
		&& (process.env.DB_BACKEND === 'postgres' || (process.env.DB_BACKEND !== 'sqlite' && process.env.DATABASE_URL))) {
		throw new Error('These commands manage SQLite only. Use Supabase database backups for the Postgres backend.');
	}
	if (command === 'migrate-supabase' && !secondPath) {
		await migrateSqliteToSupabase(firstPath || databaseFile);
		return;
	}
	if (command === 'backup' && firstPath && !secondPath) {
		const destination = path.resolve(firstPath);
		await copyDatabase(databaseFile, destination);
		console.log(`Verified SQLite backup written to ${destination}`);
		return;
	}
	if (command === 'restore' && firstPath && secondPath) {
		const source = path.resolve(firstPath);
		const destination = path.resolve(secondPath);
		await copyDatabase(source, destination);
		console.log(`Verified SQLite restore written to ${destination}`);
		return;
	}
	throw new Error('Usage: node db-tools.js backup <new-backup-file> | restore <backup-file> <new-database-file> | migrate-supabase [sqlite-file]');
}

main().catch(error => {
	console.error(`Database tool: ${error.message}`);
	process.exitCode = 1;
});