/**
 * Database initialization and access layer.
 * Uses sql.js (pure JavaScript SQLite) for zero-dependency SQLite.
 * All queries use parameterized statements to prevent SQL injection.
 */
import { type Database as SqlJsDatabase } from 'sql.js';
export declare function getDb(): SqlJsDatabase;
export declare function initDb(path: string): Promise<SqlJsDatabase>;
/** Persist database to disk */
export declare function saveDb(): void;
export declare function closeDb(): void;
/**
 * Helper: Run a parameterized INSERT/UPDATE/DELETE statement.
 */
export declare function dbRun(sql: string, params?: any[]): void;
/**
 * Helper: Run a parameterized SELECT and return all rows.
 */
export declare function dbAll(sql: string, params?: any[]): any[];
/**
 * Helper: Run a parameterized SELECT and return first row.
 */
export declare function dbGet(sql: string, params?: any[]): any | undefined;
