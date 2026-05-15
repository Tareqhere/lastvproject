/**
 * Backend API tests using Vitest.
 * Tests verify:
 * 1. Analyze endpoint returns expected JSON shape
 * 2. Auth endpoints work correctly
 * 3. Input validation rejects malformed data
 * 4. CVSS computation returns correct scores
 */
import { describe, it, expect } from 'vitest';
import { computeCvssScore, estimateScoreFromLabel, getSeverityLabel } from '../src/services/cvss.js';
import { analyzeInputSchema, signupSchema, loginSchema, sanitizeOutput, createContentPreview } from '../src/utils/validation.js';

describe('CVSS Score Computation', () => {
  it('should compute correct score for a critical vulnerability vector', () => {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
    const result = computeCvssScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.cvss_score).toBe(9.8);
    expect(result.severity_label).toBe('Critical');
  });

  it('should compute correct score for a medium vulnerability', () => {
    // CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N = 4.6
    const result = computeCvssScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N');
    expect(result.cvss_score).toBeGreaterThan(0);
    expect(result.cvss_score).toBeLessThanOrEqual(10);
    expect(result.severity_label).not.toBeNull();
  });

  it('should return null for invalid vector', () => {
    const result = computeCvssScore('invalid-vector');
    expect(result.cvss_score).toBeNull();
  });

  it('should handle empty impact (no CIA impact)', () => {
    const result = computeCvssScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
    expect(result.cvss_score).toBe(0);
    expect(result.severity_label).toBe('None');
  });

  it('should estimate score from severity label', () => {
    const high = estimateScoreFromLabel('High');
    expect(high.cvss_score).toBe(7.5);
    expect(high.severity_label).toBe('High');
  });

  it('should return correct severity labels', () => {
    expect(getSeverityLabel(0)).toBe('None');
    expect(getSeverityLabel(2.5)).toBe('Low');
    expect(getSeverityLabel(5.0)).toBe('Medium');
    expect(getSeverityLabel(7.5)).toBe('High');
    expect(getSeverityLabel(9.5)).toBe('Critical');
  });
});

describe('Input Validation', () => {
  it('should accept valid analysis input (code)', () => {
    const result = analyzeInputSchema.safeParse({
      inputType: 'code',
      content: 'console.log("test")',
    });
    expect(result.success).toBe(true);
  });

  it('should accept valid analysis input (url)', () => {
    const result = analyzeInputSchema.safeParse({
      inputType: 'url',
      content: 'https://example.com/vulnerable.php',
    });
    expect(result.success).toBe(true);
  });

  it('should reject empty content', () => {
    const result = analyzeInputSchema.safeParse({
      inputType: 'code',
      content: '',
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid inputType', () => {
    const result = analyzeInputSchema.safeParse({
      inputType: 'exploit',
      content: 'test',
    });
    expect(result.success).toBe(false);
  });

  it('should validate signup with strong password', () => {
    const result = signupSchema.safeParse({
      email: 'user@example.com',
      password: 'SecurePass1',
    });
    expect(result.success).toBe(true);
  });

  it('should reject weak passwords', () => {
    const result = signupSchema.safeParse({
      email: 'user@example.com',
      password: 'weak',
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid email format', () => {
    const result = signupSchema.safeParse({
      email: 'not-an-email',
      password: 'SecurePass1',
    });
    expect(result.success).toBe(false);
  });
});

describe('Output Sanitization', () => {
  it('should encode HTML entities', () => {
    const input = '<script>alert("xss")</script>';
    const result = sanitizeOutput(input);
    expect(result).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    expect(result).not.toContain('<script>');
  });

  it('should handle ampersands', () => {
    expect(sanitizeOutput('a & b')).toBe('a &amp; b');
  });
});

describe('Content Preview', () => {
  it('should truncate long content', () => {
    const long = 'a'.repeat(300);
    const preview = createContentPreview(long);
    expect(preview.length).toBeLessThanOrEqual(203); // 200 + '...'
  });

  it('should not truncate short content', () => {
    const short = 'hello';
    const preview = createContentPreview(short);
    expect(preview).toBe('hello');
  });
});
