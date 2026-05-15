/**
 * Authentication middleware.
 *
 * Supports two modes:
 * 1. Authenticated users: JWT token in httpOnly cookie or Authorization header
 * 2. Anonymous users: Ephemeral session ID stored in a cookie
 *
 * This middleware attaches userId and/or sessionId to the request
 * so downstream handlers can scope data access appropriately.
 */
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

// Extend Express Request to include our auth info
declare global {
  namespace Express {
    interface Request {
      userId?: string;
      sessionId?: string;
    }
  }
}

const JWT_SECRET = () => process.env.JWT_SECRET || 'dev-secret-change-me';

interface JwtPayload {
  userId: string;
  email: string;
}

/**
 * Optional auth middleware: extracts user identity if present,
 * otherwise creates/maintains an anonymous session.
 * Does NOT reject unauthenticated requests (allows anonymous usage).
 */
export function optionalAuth(req: Request, res: Response, next: NextFunction): void {
  // Try JWT from cookie first, then Authorization header
  const token = req.cookies?.auth_token || extractBearerToken(req);

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET()) as JwtPayload;
      req.userId = decoded.userId;
      return next();
    } catch {
      // Invalid/expired token — fall through to anonymous session
    }
  }

  // Anonymous session: use existing session cookie or create new one
  let sessionId = req.cookies?.session_id;
  if (!sessionId) {
    sessionId = uuidv4();
    // Set session cookie: httpOnly, secure in production, 24h expiry
    res.cookie('session_id', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });
  }
  req.sessionId = sessionId;
  next();
}

/**
 * Required auth middleware: rejects requests without a valid JWT.
 * Use this for endpoints that require a registered account.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = req.cookies?.auth_token || extractBearerToken(req);

  if (!token) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET()) as JwtPayload;
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/**
 * Generate a JWT token for an authenticated user.
 */
export function generateToken(userId: string, email: string): string {
  return jwt.sign(
    { userId, email } as JwtPayload,
    JWT_SECRET(),
    { expiresIn: '7d' } // 7-day expiry
  );
}

/**
 * Extract Bearer token from Authorization header.
 */
function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}
