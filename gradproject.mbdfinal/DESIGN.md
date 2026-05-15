# Architecture & Design Document

## System Architecture

```
┌──────────────────────────┐     ┌───────────────────────────────────┐
│     React Frontend       │     │        Express Backend            │
│  (Vite + Tailwind CSS)   │────▶│  Helmet │ CORS │ Rate Limit      │
│                          │     │  ┌──────────────────────────┐     │
│  • Input form (code/     │     │  │ Auth Middleware (JWT)     │     │
│    URL/CVE)              │     │  └──────────────────────────┘     │
│  • Auth modals           │     │  ┌──────────────────────────┐     │
│  • Report display        │     │  │ Routes                   │     │
│  • History panel         │     │  │ • POST /api/analyze      │     │
│  • Download (JSON/PDF)   │     │  │ • POST /api/signup/login │     │
│                          │     │  │ • GET/DELETE /api/reports │     │
└──────────────────────────┘     │  └──────────┬───────────────┘     │
                                 │             │                     │
                                 │  ┌──────────▼───────────────┐     │
                                 │  │ Services                 │     │
                                 │  │ • LLM Client (fetch)     │────▶ Cloud LLM API
                                 │  │ • CVSS v3.1 Engine       │     │
                                 │  │ • Zod Validation         │     │
                                 │  └──────────┬───────────────┘     │
                                 │  ┌──────────▼───────────────┐     │
                                 │  │ SQLite (sql.js)          │     │
                                 │  │ • users                  │     │
                                 │  │ • reports                │     │
                                 │  │ • audit_log              │     │
                                 │  └──────────────────────────┘     │
                                 └───────────────────────────────────┘
```

## Security Controls

### Authentication & Authorization
- **JWT tokens** stored in httpOnly, SameSite=strict cookies (not localStorage)
- **bcrypt** password hashing with cost factor 12
- **Anonymous sessions** via ephemeral cookie with 24h TTL
- Generic error messages to prevent **email enumeration**
- **Ownership verification** on every report access (404 instead of 403)

### Input Security
- **Zod validation** on every endpoint with strict schemas
- **Body size limit** (1MB) to prevent payload abuse
- **HTML entity encoding** on output to prevent XSS
- URL inputs analyzed as strings — **no active scanning** of third-party sites

### HTTP Security
- **Helmet** middleware: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **CORS** restricted to configured frontend origin
- **Rate limiting**: 100 req/15min general, 10 analysis/15min, 5 auth/15min
- Cookies: httpOnly, SameSite=strict, secure (production)

### Data Privacy
- Only content previews stored (200 chars max), not full user input
- **Hard delete** support for reports and accounts (GDPR-friendly)
- Audit logs record actions but not raw content

### AI Safety
- System prompt enforces **defensive-only** analysis
- LLM instructed to never generate exploit payloads
- Response validated against strict JSON schema
- **Retry logic** (up to 2 retries) for malformed LLM responses
- Server-side CVSS computation independent of LLM

## CVSS Scoring

The system uses CVSS v3.1 Base Score computation:

1. If the LLM returns a CVSS vector string (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), the server computes the score independently using the FIRST.org specification
2. If only a severity label is returned, a mid-range representative score is used:
   - None: 0.0, Low: 2.0, Medium: 5.5, High: 7.5, Critical: 9.5
3. The server-computed score takes precedence over the LLM's score

## OWASP Mapping

The LLM maps vulnerabilities to OWASP Top 10 2021 categories when applicable. Common mappings:
- SQL Injection → A03:2021 – Injection
- XSS → A03:2021 – Injection
- Broken Access Control → A01:2021 – Broken Access Control
- Sensitive Data Exposure → A02:2021 – Cryptographic Failures

## Database Schema

Three tables with parameterized queries throughout:

- `users`: id, email, password_hash, timestamps
- `reports`: id, user_id (nullable), session_id, input_type, content_preview (truncated), result JSON, timestamp
- `audit_log`: id, action, user_id, session_id, IP (anonymizable), details, timestamp

Foreign key cascade ensures user deletion removes all associated reports.
