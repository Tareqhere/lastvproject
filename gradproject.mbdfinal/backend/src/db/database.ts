/**
 * Database initialization and access layer.
 * Uses sql.js (pure JavaScript SQLite) for zero-dependency SQLite.
 * All queries use parameterized statements to prevent SQL injection.
 */
import initSqlJs, { type Database as SqlJsDatabase } from 'sql.js';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let db: SqlJsDatabase;
let dbPath: string;
let saveInterval: ReturnType<typeof setInterval>;

export function getDb(): SqlJsDatabase {
  if (!db) {
    throw new Error('Database not initialized. Call initDb() first.');
  }
  return db;
}

export async function initDb(path: string): Promise<SqlJsDatabase> {
  dbPath = path;

  // Ensure directory exists
  mkdirSync(dirname(path), { recursive: true });

  const SQL = await initSqlJs();

  // Load existing database or create new one
  if (existsSync(path)) {
    const fileBuffer = readFileSync(path);
    db = new SQL.Database(fileBuffer);
    console.log('[DB] Loaded existing database from', path);
  } else {
    db = new SQL.Database();
    console.log('[DB] Created new database at', path);
  }

  // Enable foreign keys
  db.run('PRAGMA foreign_keys = ON');

  // Run schema migration
  const schemaPath = join(__dirname, 'schema.sql');
  const schema = readFileSync(schemaPath, 'utf-8');
  db.run(schema);

  // Auto-save to disk every 5 seconds
  saveInterval = setInterval(() => saveDb(), 5000);

  console.log('[DB] Database initialized');
  return db;
}

/** Persist database to disk */
export function saveDb(): void {
  if (db && dbPath) {
    try {
      const data = db.export();
      const buffer = Buffer.from(data);
      writeFileSync(dbPath, buffer);
    } catch (err) {
      console.error('[DB] Failed to save database:', err);
    }
  }
}

export function closeDb(): void {
  if (saveInterval) {
    clearInterval(saveInterval);
  }
  if (db) {
    saveDb(); // Final save
    db.close();
    console.log('[DB] Database connection closed');
  }
}

/**
 * Helper: Run a parameterized INSERT/UPDATE/DELETE statement.
 */
export function dbRun(sql: string, params: any[] = []): void {
  getDb().run(sql, params);
}

/**
 * Helper: Run a parameterized SELECT and return all rows.
 */
export function dbAll(sql: string, params: any[] = []): any[] {
  const stmt = getDb().prepare(sql);
  if (params.length > 0) {
    stmt.bind(params);
  }
  const results: any[] = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

/**
 * Helper: Run a parameterized SELECT and return first row.
 */
export function dbGet(sql: string, params: any[] = []): any | undefined {
  const rows = dbAll(sql, params);
  return rows.length > 0 ? rows[0] : undefined;
}
