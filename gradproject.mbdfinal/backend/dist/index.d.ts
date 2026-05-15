/**
 * Main Express application entry point.
 *
 * SECURITY MIDDLEWARE STACK:
 * 1. Helmet — sets secure HTTP headers (CSP, HSTS, X-Frame-Options, etc.)
 * 2. CORS — restricts cross-origin requests to allowed frontend origin
 * 3. Rate limiting — prevents brute force and abuse
 * 4. Cookie parser — handles httpOnly auth and session cookies
 * 5. JSON body parser — with size limit to prevent payload abuse
 * 6. Input validation — via Zod schemas in each route
 */
import 'dotenv/config';
declare const app: import("express-serve-static-core").Express;
export default app;
