/**
 * Analysis route: POST /api/analyze
 *
 * Accepts user input (code, URL, or text), sends it to the cloud LLM
 * for defensive security analysis, validates the response, computes
 * CVSS scores, and stores the report.
 *
 * SECURITY:
 * - Input validated with Zod schemas
 * - URL inputs are analyzed as strings (no active scanning/fetching)
 * - LLM response validated against expected schema
 * - CVSS scores verified/computed server-side
 * - Content previews stored (not full input) for privacy
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { dbRun, saveDb } from '../db/database.js';
import { analyzeInputSchema, createContentPreview } from '../utils/validation.js';
import { analyzeWithLlm } from '../services/llm.js';
import { computeCvssScore, estimateScoreFromLabel, getSeverityLabel } from '../services/cvss.js';
import { auditLog } from '../utils/audit.js';
import { buildRiskMap, calculateConfidence } from '../services/cveLookup.js';
import type { RiskMapEntryWithMeta } from '../services/cveLookup.js';
import { enrichMitreMapping } from '../services/mitreEnrichment.js';

const router = Router();

/**
 * Map the frontend's inputType values to the backend's expected format.
 * Frontend uses 'cve' but backend/LLM expects 'text' for CVE descriptions.
 */
function normalizeInputType(inputType: string): string {
  if (inputType === 'cve') return 'text';
  if (inputType === 'link') return 'url';
  return inputType;
}

router.post('/', async (req: Request, res: Response) => {
  try {
    // Validate input
    const result = analyzeInputSchema.safeParse({
      inputType: normalizeInputType(req.body.inputType),
      content: req.body.content,
    });

    if (!result.success) {
      res.status(400).json({
        error: 'Validation failed',
        details: result.error.issues.map((i) => i.message),
      });
      return;
    }

    const { inputType, content } = result.data;

    auditLog({
      action: 'analysis.request',
      userId: req.userId ?? null,
      sessionId: req.sessionId ?? null,
      ipAddress: req.ip,
      details: `inputType=${inputType}, contentLength=${content.length}`,
    });

    // Call LLM for analysis
    let llmResult;
    try {
      llmResult = await analyzeWithLlm(inputType, content);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      console.error('[ANALYZE] LLM error:', errorMessage);

      auditLog({
        action: 'analysis.error',
        userId: req.userId ?? null,
        sessionId: req.sessionId ?? null,
        ipAddress: req.ip,
        details: `LLM analysis failed: ${errorMessage}`,
      });

      res.status(502).json({
        error: 'Analysis service temporarily unavailable',
        message: 'The AI analysis engine could not process this request. Please try again later.',
      });
      return;
    }

    // Server-side CVSS score computation/verification for each vulnerability
    const vulnerabilities = llmResult.vulnerabilities.map((vuln) => {
      let cvssResult;
      if (vuln.cvss_vector) {
        // If LLM provided a vector, compute score server-side for verification
        cvssResult = computeCvssScore(vuln.cvss_vector);
      } else if (vuln.severity_label) {
        // If only severity label provided, estimate a representative score
        cvssResult = estimateScoreFromLabel(vuln.severity_label);
      } else {
        cvssResult = { cvss_score: null, cvss_vector: null, severity_label: null };
      }

      // CVSS score and severity are locked here — dataset must not override them.
      const cvss_score = cvssResult.cvss_score ?? vuln.cvss_score ?? null;
      const cvss_vector = cvssResult.cvss_vector ?? vuln.cvss_vector ?? null;

      // severity_label is derived ONLY from the CVSS score, never from the dataset.
      const severity_label: string | null =
        cvss_score !== null
          ? getSeverityLabel(cvss_score)
          : cvssResult.severity_label ?? vuln.severity_label ?? null;

      return {
        ...vuln,
        cvss_score,
        cvss_vector,
        severity_label,
      };
    });

    // Apply CSV-first MITRE ATT&CK mapping.
    // For each vulnerability, look up its type in the MITRE enrichment CSV.
    // If found, replace the AI-generated mitre_attack_mapping with the
    // authoritative CSV entry.  If not found, the AI mapping is kept as-is.
    // No other field is modified here.
    const mitreEnrichedVulnerabilities = vulnerabilities.map((vuln) => ({
      ...vuln,
      mitre_attack_mapping: enrichMitreMapping(
        vuln.vulnerability_type,
        vuln.mitre_attack_mapping,
      ),
    }));

    // Build CVE-enriched risk map and override severities BEFORE sorting
    const riskMapWithMeta: RiskMapEntryWithMeta[] = buildRiskMap(mitreEnrichedVulnerabilities, content);

    // Apply evidence-based confidence to each vulnerability, using match metadata
    const enrichedVulnerabilities = mitreEnrichedVulnerabilities.map((vuln, i) => {
      const meta = riskMapWithMeta[i];
      const matchMethod = meta?._matchMethod ?? 'none';

      const { confidence, reason } = calculateConfidence(
        vuln.vulnerability_type,
        vuln.explanation ?? '',
        matchMethod,
        vuln.confidence,
      );

      // Dev log for validation
      console.log(
        `[SCORING] vulnerability_type="${vuln.vulnerability_type}"` +
        ` | cvss_score=${vuln.cvss_score}` +
        ` | severity_label="${vuln.severity_label}"` +
        ` | dataset_match=${matchMethod}` +
        ` | final_confidence=${confidence}` +
        ` | confidence_reason="${reason}"`
      );

      return { ...vuln, confidence };
    });

    // Strip internal metadata before sending — consumers must not see _matchMethod
    const riskMap = riskMapWithMeta.map(({ _matchMethod: _m, ...entry }) => entry);

    // Sort vulnerabilities by severity then name
    const severityOrder: Record<string, number> = {
      'Critical': 4,
      'High': 3,
      'Medium': 2,
      'Low': 1,
      'None': 0,
    };

    enrichedVulnerabilities.sort((a, b) => {
      const sevA = severityOrder[a.severity_label || 'None'] ?? -1;
      const sevB = severityOrder[b.severity_label || 'None'] ?? -1;
      if (sevA !== sevB) {
        return sevB - sevA; // descending severity
      }
      return (a.vulnerability_type || '').localeCompare(b.vulnerability_type || '');
    });

    // Build the final report
    const reportResult = {
      is_vulnerable: llmResult.is_vulnerable,
      vulnerabilities: enrichedVulnerabilities,
      riskMap,
    };

    // Store the report
    const reportId = uuidv4();
    const contentPreview = createContentPreview(content);

    dbRun(
      "INSERT INTO reports (id, user_id, session_id, input_type, content_preview, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
      [
        reportId,
        req.userId ?? null,
        req.sessionId ?? null,
        inputType,
        contentPreview,
        JSON.stringify(reportResult),
      ]
    );
    saveDb();

    auditLog({
      action: 'report.create',
      userId: req.userId ?? null,
      sessionId: req.sessionId ?? null,
      ipAddress: req.ip,
      details: `reportId=${reportId}`,
    });

    res.status(201).json({
      id: reportId,
      inputType,
      contentPreview,
      result: reportResult,
      createdAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[ANALYZE] Unexpected error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
