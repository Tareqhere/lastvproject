# Security Checklist — Before Public Deployment

Complete all items before exposing this application to the internet.

## Secrets & Configuration
- [ ] Generate a strong random `JWT_SECRET` (at least 32 characters)
- [ ] Set `LLM_API_KEY` to a valid, scoped API key
- [ ] Set `NODE_ENV=production`
- [ ] Ensure no secrets are committed to version control
- [ ] Set `CORS_ORIGIN` to exact frontend domain (not `*`)

## Transport Security
- [ ] Enable HTTPS (TLS certificate via Let's Encrypt or cloud provider)
- [ ] Verify HSTS header is present (`Strict-Transport-Security`)
- [ ] Redirect all HTTP traffic to HTTPS

## Authentication
- [ ] Verify cookies have `Secure`, `HttpOnly`, and `SameSite=Strict` flags
- [ ] Test that JWT expiry works correctly (7-day default)
- [ ] Confirm rate limiting on auth endpoints (5 req/15min)
- [ ] Test failed login does not reveal whether email exists

## Input Validation
- [ ] Test all input validation with malformed data
- [ ] Verify body size limit rejects payloads > 1MB
- [ ] Confirm HTML encoding works on all output fields
- [ ] Test with known XSS payloads (should be safely encoded)

## Database
- [ ] Ensure database file is not publicly accessible
- [ ] Verify all queries use parameterized statements (grep for string concatenation)
- [ ] Test CASCADE delete works when deleting user accounts
- [ ] Back up database regularly in production

## Rate Limiting
- [ ] Verify general rate limit: 100 requests / 15 minutes
- [ ] Verify analysis rate limit: 10 requests / 15 minutes
- [ ] Verify auth rate limit: 5 requests / 15 minutes
- [ ] Consider adding IP-based banning for persistent abuse

## AI Safety
- [ ] Test that LLM never returns exploit payloads
- [ ] Verify system prompt is not exposed in API responses
- [ ] Test retry logic for malformed LLM responses
- [ ] Monitor LLM API costs and set spending limits

## Headers & CORS
- [ ] Verify Content-Security-Policy is set
- [ ] Verify X-Frame-Options: DENY (via Helmet)
- [ ] Verify X-Content-Type-Options: nosniff
- [ ] Test CORS rejects requests from unauthorized origins

## Privacy & Compliance
- [ ] Verify content previews don't store sensitive data
- [ ] Test hard delete on reports and accounts
- [ ] Consider adding a privacy policy page
- [ ] Ensure audit logs don't contain PII
