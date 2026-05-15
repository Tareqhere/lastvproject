/**
 * LLM API integration service.
 *
 * Handles communication with the cloud LLM for vulnerability analysis.
 * Enforces defensive-only analysis through system prompt engineering.
 *
 * SECURITY: The system prompt explicitly prohibits exploit generation,
 * and the response is validated against a known-good JSON schema.
 */
import { type LlmResponse } from '../utils/validation.js';
/**
 * Call the LLM API and parse the response.
 * Includes retry logic for malformed responses (up to MAX_RETRIES).
 */
export declare function analyzeWithLlm(inputType: string, content: string): Promise<LlmResponse>;
