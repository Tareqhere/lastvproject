/**
 * Authentication routes: signup, login, logout.
 *
 * SECURITY:
 * - Passwords hashed with bcrypt (cost factor 12)
 * - JWT stored in httpOnly, SameSite=strict cookies
 * - Rate limiting applied at the router level
 * - Constant-time comparison via bcrypt.compare
 * - No password or hash ever returned in responses
 */
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { dbRun, dbGet, saveDb } from '../db/database.js';
import { signupSchema, loginSchema } from '../utils/validation.js';
import { generateToken } from '../middleware/auth.js';
import { auditLog } from '../utils/audit.js';
const router = Router();
// Bcrypt cost factor — 12 provides good security/performance balance
const BCRYPT_ROUNDS = 12;
/**
 * POST /api/signup
 * Create a new user account with email and password.
 */
router.post('/signup', async (req, res) => {
    try {
        // Validate input
        const result = signupSchema.safeParse(req.body);
        if (!result.success) {
            res.status(400).json({
                error: 'Validation failed',
                details: result.error.issues.map((i) => i.message),
            });
            return;
        }
        const { email, password } = result.data;
        // Check if email already exists (parameterized query)
        const existing = dbGet('SELECT id FROM users WHERE email = ?', [email]);
        if (existing) {
            res.status(409).json({ error: 'An account with this email already exists' });
            return;
        }
        // Hash password with bcrypt
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();
        // Insert user (parameterized query prevents SQL injection)
        dbRun('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)', [userId, email, passwordHash]);
        saveDb();
        // Generate JWT
        const token = generateToken(userId, email);
        // Set secure httpOnly cookie
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        // Clear anonymous session cookie since user is now authenticated
        res.clearCookie('session_id');
        auditLog({
            action: 'user.signup',
            userId,
            ipAddress: req.ip,
            details: 'Account created',
        });
        res.status(201).json({
            message: 'Account created successfully',
            user: { id: userId, email },
        });
    }
    catch (err) {
        console.error('[AUTH] Signup error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /api/login
 * Authenticate user and return JWT.
 */
router.post('/login', async (req, res) => {
    try {
        const result = loginSchema.safeParse(req.body);
        if (!result.success) {
            res.status(400).json({
                error: 'Validation failed',
                details: result.error.issues.map((i) => i.message),
            });
            return;
        }
        const { email, password } = result.data;
        // Fetch user by email (parameterized query)
        const user = dbGet('SELECT id, email, password_hash FROM users WHERE email = ?', [email]);
        if (!user) {
            // Use generic error to prevent email enumeration
            auditLog({
                action: 'auth.failed',
                ipAddress: req.ip,
                details: 'Invalid credentials',
            });
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }
        // Constant-time password comparison via bcrypt
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            auditLog({
                action: 'auth.failed',
                userId: user.id,
                ipAddress: req.ip,
                details: 'Invalid credentials',
            });
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }
        const token = generateToken(user.id, user.email);
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.clearCookie('session_id');
        auditLog({
            action: 'user.login',
            userId: user.id,
            ipAddress: req.ip,
        });
        res.json({
            message: 'Login successful',
            user: { id: user.id, email: user.email },
        });
    }
    catch (err) {
        console.error('[AUTH] Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * POST /api/logout
 * Clear authentication cookies.
 */
router.post('/logout', (req, res) => {
    const userId = req.userId;
    res.clearCookie('auth_token');
    res.clearCookie('session_id');
    if (userId) {
        auditLog({
            action: 'user.logout',
            userId,
            ipAddress: req.ip,
        });
    }
    res.json({ message: 'Logged out successfully' });
});
/**
 * GET /api/me
 * Get current authenticated user info.
 */
router.get('/me', (req, res) => {
    if (!req.userId) {
        res.json({ authenticated: false });
        return;
    }
    const user = dbGet('SELECT id, email, created_at FROM users WHERE id = ?', [req.userId]);
    if (!user) {
        res.json({ authenticated: false });
        return;
    }
    res.json({
        authenticated: true,
        user: { id: user.id, email: user.email, createdAt: user.created_at },
    });
});
/**
 * DELETE /api/account
 * Delete user account and all associated data (hard delete).
 * GDPR-friendly: removes all user data including reports.
 */
router.delete('/account', async (req, res) => {
    if (!req.userId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
    }
    try {
        // Delete all user reports first (cascade should handle this, but explicit is safer)
        dbRun('DELETE FROM reports WHERE user_id = ?', [req.userId]);
        // Delete the user account
        dbRun('DELETE FROM users WHERE id = ?', [req.userId]);
        saveDb();
        res.clearCookie('auth_token');
        auditLog({
            action: 'user.delete',
            userId: req.userId,
            ipAddress: req.ip,
            details: 'Account and all data deleted',
        });
        res.json({ message: 'Account and all associated data deleted' });
    }
    catch (err) {
        console.error('[AUTH] Account deletion error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
export default router;
