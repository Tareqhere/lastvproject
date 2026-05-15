/**
 * Reports routes: CRUD operations for analysis reports.
 *
 * SECURITY:
 * - All queries use parameterized statements
 * - Ownership verification on every access (user or session scoping)
 * - Hard delete support for privacy compliance
 */
import { Router } from 'express';
import { dbRun, dbAll, dbGet, saveDb } from '../db/database.js';
import { auditLog } from '../utils/audit.js';
const router = Router();
/**
 * GET /api/reports
 * List reports for the current user or anonymous session.
 */
router.get('/', (req, res) => {
    try {
        let reports;
        if (req.userId) {
            // Authenticated user: get their reports
            reports = dbAll('SELECT id, input_type, content_preview, result_json, created_at FROM reports WHERE user_id = ? ORDER BY created_at DESC', [req.userId]);
        }
        else if (req.sessionId) {
            // Anonymous user: get session reports
            reports = dbAll('SELECT id, input_type, content_preview, result_json, created_at FROM reports WHERE session_id = ? AND user_id IS NULL ORDER BY created_at DESC', [req.sessionId]);
        }
        else {
            reports = [];
        }
        const formattedReports = reports.map((r) => ({
            id: r.id,
            inputType: r.input_type,
            contentPreview: r.content_preview,
            result: JSON.parse(r.result_json),
            createdAt: r.created_at,
        }));
        res.json({ reports: formattedReports });
    }
    catch (err) {
        console.error('[REPORTS] List error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * GET /api/reports/:id
 * Fetch a single report by ID (with ownership verification).
 */
router.get('/:id', (req, res) => {
    try {
        const report = dbGet('SELECT id, user_id, session_id, input_type, content_preview, result_json, created_at FROM reports WHERE id = ?', [req.params.id]);
        if (!report) {
            res.status(404).json({ error: 'Report not found' });
            return;
        }
        // Ownership check: user can only access their own reports
        const isOwner = (req.userId && report.user_id === req.userId) ||
            (req.sessionId && report.session_id === req.sessionId && !report.user_id);
        if (!isOwner) {
            // Return 404 instead of 403 to prevent report ID enumeration
            res.status(404).json({ error: 'Report not found' });
            return;
        }
        res.json({
            id: report.id,
            inputType: report.input_type,
            contentPreview: report.content_preview,
            result: JSON.parse(report.result_json),
            createdAt: report.created_at,
        });
    }
    catch (err) {
        console.error('[REPORTS] Get error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * DELETE /api/reports/:id
 * Hard delete a report (with ownership verification).
 * GDPR/privacy-friendly: completely removes the data.
 */
router.delete('/:id', (req, res) => {
    try {
        const report = dbGet('SELECT id, user_id, session_id FROM reports WHERE id = ?', [req.params.id]);
        if (!report) {
            res.status(404).json({ error: 'Report not found' });
            return;
        }
        // Ownership check
        const isOwner = (req.userId && report.user_id === req.userId) ||
            (req.sessionId && report.session_id === req.sessionId && !report.user_id);
        if (!isOwner) {
            res.status(404).json({ error: 'Report not found' });
            return;
        }
        dbRun('DELETE FROM reports WHERE id = ?', [req.params.id]);
        saveDb();
        auditLog({
            action: 'report.delete',
            userId: req.userId ?? null,
            sessionId: req.sessionId ?? null,
            ipAddress: req.ip,
            details: `reportId=${req.params.id}`,
        });
        res.json({ message: 'Report deleted successfully' });
    }
    catch (err) {
        console.error('[REPORTS] Delete error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
export default router;
