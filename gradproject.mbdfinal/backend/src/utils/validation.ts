/**
 * Input validation schemas using Zod.
 * Centralizes all validation logic to ensure consistent input handling.
 * Every user-facing input is validated before processing.
 */
import { z } from 'zod';

// Analysis request validation
export const analyzeInputSchema = z.object({
  inputType: z.enum(['code', 'url', 'text'], {
    errorMap: () => ({ message: 'inputType must be one of: code, url, text' }),
  }),
  content: z
    .string()
    .min(1, 'Content cannot be empty')
    .max(50000, 'Content exceeds maximum length of 50,000 characters'),
});

// Auth schemas
export const signupSchema = z.object({
  email: z
    .string()
    .email('Invalid email format')
    .max(255, 'Email too long'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password too long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
      'Password must contain at least one lowercase letter, one uppercase letter, and one digit'
    ),
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
});

export const vulnerabilitySchema = z.object({
  vulnerability_type: z.string().nullable(),
  owasp_category: z.string().nullable(),
  cvss_vector: z.string().nullable().optional(),
  cvss_score: z.number().min(0).max(10).nullable().optional(),
  severity_label: z.enum(['None', 'Low', 'Medium', 'High', 'Critical']).nullable(),
  explanation: z.string(),
  secure_patch: z.string(),
  recommendations: z.array(z.string()),
  confidence: z.enum(['Low', 'Medium', 'High']),
  mitre_attack_mapping: z.array(z.object({
    technique_id: z.string(),
    technique_name: z.string(),
    explanation: z.string(),
  })).optional(),
  notes: z.string().nullable().optional(),
});

// LLM response validation - validates the expected JSON schema from the AI model
export const llmResponseSchema = z.object({
  is_vulnerable: z.boolean(),
  vulnerabilities: z.array(vulnerabilitySchema),
});

export type AnalyzeInput = z.infer<typeof analyzeInputSchema>;
export type SignupInput = z.infer<typeof signupSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type Vulnerability = z.infer<typeof vulnerabilitySchema>;
export type LlmResponse = z.infer<typeof llmResponseSchema>;

/**
 * Sanitize a string for safe output (basic HTML entity encoding).
 * Prevents XSS when rendering user-provided content.
 */
export function sanitizeOutput(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Truncate content for safe preview storage (no full user input in DB previews).
 */
export function createContentPreview(content: string, maxLength = 200): string {
  const trimmed = content.trim().substring(0, maxLength);
  return trimmed.length < content.trim().length ? trimmed + '...' : trimmed;
}
