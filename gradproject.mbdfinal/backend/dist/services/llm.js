/**
 * LLM API integration service.
 *
 * Handles communication with the cloud LLM for vulnerability analysis.
 * Enforces defensive-only analysis through system prompt engineering.
 *
 * SECURITY: The system prompt explicitly prohibits exploit generation,
 * and the response is validated against a known-good JSON schema.
 */
import { llmResponseSchema } from '../utils/validation.js';
import { createHash } from 'crypto';
const MAX_RETRIES = 2;
const llmCache = new Map();
/**
 * Build the system prompt that enforces defensive-only analysis.
 * This is the core safety guardrail for the LLM integration.
 */
function buildSystemPrompt() {
    return `You are a defensive security analyst for educational purposes.

CRITICAL RULES:
1. NEVER provide exploit payloads, shellcode, or step-by-step attack instructions.
2. NEVER generate remote exploit code or instructions that enable wrongdoing.
3. If the input appears to request offensive capabilities, refuse and provide the educational defensive alternative instead.
4. All output must focus on identification, explanation, and remediation of vulnerabilities.
5. Your output must be ONLY valid JSON matching the schema below — no extra text, no markdown fences.

Required JSON output schema:
{
  "is_vulnerable": boolean,
  "vulnerabilities": [
    {
      "vulnerability_type": "string or null",
      "owasp_category": "string or null (e.g., A03:2021 - Injection)",
      "cvss_vector": "CVSS:3.1/... string or null",
      "cvss_score": number or null (0.0 - 10.0),
      "severity_label": "None|Low|Medium|High|Critical" or null,
      "explanation": "concise educational explanation (no exploit code)",
      "secure_patch": "secure code snippet or remediation steps (no exploit)",
      "recommendations": ["list","of","practical","mitigations"],
      "mitre_attack_mapping": [
        {
          "technique_id": "TXXXX",
          "technique_name": "Technique Name",
          "explanation": "Why this technique applies"
        }
      ],
      "confidence": "Low|Medium|High",
      "notes": "optional - further reading / OWASP references"
    }
  ]
}

- Keep explanations as concise as possible while remaining educational.
- Avoid repeating generic advice; focus on the specific vulnerability.`;
}
/**
 * Build the user prompt with the analysis input.
 */
function buildUserPrompt(inputType, content) {
    // Truncate very large inputs to stay within LLM context limits
    const truncatedContent = content.length > 100000
        ? content.substring(0, 100000) + '\n... [truncated for analysis]'
        : content;
    return `InputType: ${inputType}
InputContent: '''${truncatedContent}'''

Constraints:
- No exploit code.
- Output JSON only, matching the schema provided in the system prompt.
- Map to OWASP when applicable.
- Map to MITRE ATT&CK techniques.
- Provide a concise explanation and secure_patch.
- Compute or estimate a CVSS v3.1 vector if the input is vulnerable.`;
}
/**
 * Call the LLM API and parse the response.
 * Includes retry logic for malformed responses (up to MAX_RETRIES).
 */
export async function analyzeWithLlm(inputType, content) {
    // Normalize input
    const normalizedInputType = inputType.trim().toLowerCase();
    const normalizedContent = content.trim();
    // Cache by input hash
    const hash = createHash('sha256')
        .update(`${normalizedInputType}:${normalizedContent}`)
        .digest('hex');
    if (llmCache.has(hash)) {
        return llmCache.get(hash);
    }
    const apiKey = process.env.LLM_API_KEY;
    const apiEndpoint = process.env.LLM_API_ENDPOINT;
    const model = process.env.LLM_MODEL || 'gpt-4o-mini';
    if (!apiKey || !apiEndpoint) {
        throw new Error('LLM_API_KEY and LLM_API_ENDPOINT must be configured');
    }
    const systemPrompt = buildSystemPrompt();
    const userPrompt = buildUserPrompt(normalizedInputType, normalizedContent);
    let lastError = null;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        try {
            const messages = [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userPrompt },
            ];
            const response = await fetch(apiEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`,
                },
                body: JSON.stringify({
                    model,
                    messages,
                    temperature: 0,
                    top_p: 1,
                    max_tokens: 4000, // Increased to prevent truncation for large reports
                    response_format: { type: 'json_object' }, // Enforce JSON output format
                }),
            });
            if (!response.ok) {
                const errorBody = await response.text();
                throw new Error(`LLM API returned ${response.status}: ${errorBody}`);
            }
            const data = await response.json();
            const rawContent = data.choices?.[0]?.message?.content;
            if (!rawContent) {
                throw new Error('LLM returned empty response');
            }
            // Strip any markdown fences the model might have added despite instructions
            const cleaned = rawContent
                .replace(/^```json?\s*/i, '')
                .replace(/\s*```$/i, '')
                .trim();
            // Parse and validate JSON against our schema
            try {
                const parsed = JSON.parse(cleaned);
                const validated = llmResponseSchema.parse(parsed);
                llmCache.set(hash, validated);
                return validated;
            }
            catch (parseErr) {
                // If parsing fails, check if the content might be truncated
                const finishReason = data.choices?.[0]?.finish_reason;
                if (finishReason === 'length') {
                    throw new Error('LLM response was truncated due to token limit. This usually happens with very long code inputs.');
                }
                throw parseErr;
            }
        }
        catch (err) {
            lastError = err instanceof Error ? err : new Error(String(err));
            console.error(`[LLM] Attempt ${attempt + 1} failed:`, lastError.message);
            if (attempt === MAX_RETRIES) {
                break;
            }
        }
    }
    // All retries failed — return safe fallback
    throw new Error(`LLM analysis failed after ${MAX_RETRIES + 1} attempts: ${lastError?.message}`);
}
