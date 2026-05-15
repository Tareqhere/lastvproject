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
declare global {
    namespace Express {
        interface Request {
            userId?: string;
            sessionId?: string;
        }
    }
}
/**
 * Optional auth middleware: extracts user identity if present,
 * otherwise creates/maintains an anonymous session.
 * Does NOT reject unauthenticated requests (allows anonymous usage).
 */
export declare function optionalAuth(req: Request, res: Response, next: NextFunction): void;
/**
 * Required auth middleware: rejects requests without a valid JWT.
 * Use this for endpoints that require a registered account.
 */
export declare function requireAuth(req: Request, res: Response, next: NextFunction): void;
/**
 * Generate a JWT token for an authenticated user.
 */
export declare function generateToken(userId: string, email: string): string;
