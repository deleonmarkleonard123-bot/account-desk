const { DatabaseSync, backup } = require('node:sqlite');
const fs = require('node:fs/promises');
const path = require('node:path');
require('dotenv').config();

const root = __dirname;
const databaseFile = path.resolve(process.env.DB_PATH || path.join(root, 'data', 'accounts.sqlite'));

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

async function main() {
	const [command, firstPath, secondPath] = process.argv.slice(2);
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
	throw new Error('Usage: node db-tools.js backup <new-backup-file> | restore <backup-file> <new-database-file>');
}

main().catch(error => {
	console.error(`Database tool: ${error.message}`);
	process.exitCode = 1;
});