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
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { initDb, closeDb } from './db/database.js';
import { optionalAuth } from './middleware/auth.js';
import authRoutes from './routes/auth.js';
import analyzeRoutes from './routes/analyze.js';
import reportsRoutes from './routes/reports.js';
import { loadVulnerabilityDataset } from './services/cveLookup.js';
import { loadMitreDataset } from './services/mitreEnrichment.js';

const app = express();

// ──────────────────────────────────────────────
// 1. Security Headers via Helmet
// ──────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Required for Tailwind inline styles
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],             // Clickjacking prevention
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    // HSTS: enforce HTTPS in production
    strictTransportSecurity: {
      maxAge: 31536000,        // 1 year
      includeSubDomains: true,
      preload: true,
    },
  })
);

// ──────────────────────────────────────────────
// 2. CORS Configuration
// ──────────────────────────────────────────────
const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';
app.use(
  cors({
    origin: corsOrigin,
    credentials: true,              // Allow cookies
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// ──────────────────────────────────────────────
// 3. Rate Limiting
// ──────────────────────────────────────────────
// General rate limit: 100 requests per 15 minutes per IP
const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

// Stricter rate limit for analysis endpoint: 10 per 15 minutes
const analysisLimiter = rateLimit({
  windowMs: 900000, // 15 minutes
  max: parseInt(process.env.ANALYSIS_RATE_LIMIT_MAX || '10'),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Analysis rate limit exceeded. Please wait before submitting again.' },
});

// Auth endpoint rate limit: 5 per 15 minutes to prevent brute force
const authLimiter = rateLimit({
  windowMs: 900000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' },
});

app.use(generalLimiter);

// ──────────────────────────────────────────────
// 4. Body Parsing & Cookies
// ──────────────────────────────────────────────
// Limit request body to 1MB to prevent abuse
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// ──────────────────────────────────────────────
// 5. Auth Middleware (applies to all routes)
// ──────────────────────────────────────────────
app.use(optionalAuth);

// ──────────────────────────────────────────────
// 6. API Routes
// ──────────────────────────────────────────────
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api', authRoutes);
app.use('/api/analyze', analysisLimiter, analyzeRoutes);
app.use('/api/reports', reportsRoutes);

// ──────────────────────────────────────────────
// 7. Health Check
// ──────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ──────────────────────────────────────────────
// 8. Start Server (async for sql.js initialization)
// ──────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3001');
const DB_PATH = process.env.DB_PATH || './data/analyzer.db';

async function start() {
  try {
    // Initialize database (async for sql.js WASM loading)
    await initDb(DB_PATH);

    // Load vulnerability enrichment dataset once into memory
    const csvPath = process.env.VULNERABILITY_DATASET_PATH || './data/vulnerability_type_risk_dataset.csv';
    loadVulnerabilityDataset(csvPath);

    // Load MITRE ATT&CK enrichment CSV once into memory
    const mitreCsvPath = process.env.MITRE_CSV_PATH || './data/vulnerability_mitre_enriched.csv';
    loadMitreDataset(mitreCsvPath);

    const server = app.listen(PORT, () => {
      console.log(`[SERVER] Vulnerability Analyzer API running on port ${PORT}`);
      console.log(`[SERVER] CORS origin: ${corsOrigin}`);
      console.log(`[SERVER] Environment: ${process.env.NODE_ENV || 'development'}`);
    });

    // Graceful shutdown
    const shutdown = () => {
      console.log('\n[SERVER] Shutting down gracefully...');
      closeDb();
      server.close(() => {
        process.exit(0);
      });
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  } catch (err) {
    console.error('[SERVER] Failed to start:', err);
    process.exit(1);
  }
}

start();

export default app;
