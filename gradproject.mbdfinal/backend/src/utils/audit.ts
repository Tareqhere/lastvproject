/**
 * Audit logging utility.
 * Records security-relevant actions for accountability
 * while protecting user privacy (no raw content stored).
 */
import { dbRun } from '../db/database.js';

export type AuditAction =
  | 'user.signup'
  | 'user.login'
  | 'user.logout'
  | 'user.delete'
  | 'report.create'
  | 'report.delete'
  | 'analysis.request'
  | 'analysis.error'
  | 'auth.failed';

interface AuditEntry {
  action: AuditAction;
  userId?: string | null;
  sessionId?: string | null;
  ipAddress?: string;
  details?: string;
}

/**
 * Write an audit log entry. Uses parameterized queries to prevent injection.
 */
export function auditLog(entry: AuditEntry): void {
  try {
    dbRun(
      "INSERT INTO audit_log (action, user_id, session_id, ip_address, details, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
      [
        entry.action,
        entry.userId ?? null,
        entry.sessionId ?? null,
        entry.ipAddress ?? null,
        entry.details ?? null,
      ]
    );
  } catch (err) {
    // Audit logging should never crash the application
    console.error('[AUDIT] Failed to write audit log:', err);
  }
}
