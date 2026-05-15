export type AuditAction = 'user.signup' | 'user.login' | 'user.logout' | 'user.delete' | 'report.create' | 'report.delete' | 'analysis.request' | 'analysis.error' | 'auth.failed';
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
export declare function auditLog(entry: AuditEntry): void;
export {};
