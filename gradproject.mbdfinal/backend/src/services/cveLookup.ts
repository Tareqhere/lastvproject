/**
 * CVE/EPSS enrichment layer.
 *
 * Loads the local CSV dataset ONCE at startup into an in-memory Map.
 * All subsequent lookups are O(1) hash-map accesses.
 *
 * IMPORTANT: Dataset values (EPSS, likelihood, impact) are used ONLY for
 * the Risk Map. They must NEVER override cvss_score or severity_label,
 * which are derived exclusively from the CVSS vector.
 */
import { readFileSync } from 'fs';
import { resolve } from 'path';

export interface VulnerabilityRecord {
  vulnerability_type: string;
  likelihood: number;
  impact: number;
  epss_score: number;
  normalized_type?: string;
}

export function normalizeForMatch(str: string): string {
  if (!str) return '';
  let s = str.toLowerCase().trim();
  s = s.replace(/[()]/g, '');
  s = s.replace(/[-_]/g, ' ');
  s = s.replace(/[^\w\s]/g, '');
  s = s.replace(/\s+/g, ' ');
  return s.trim();
}

const ALIASES: Record<string, string> = {
  'sql injection': "improper neutralization of special elements used in an sql command ('sql injection')",
  'cross-site scripting (xss)': "improper neutralization of input during web page generation ('cross-site scripting')",
  'xss': "improper neutralization of input during web page generation ('cross-site scripting')",
  'command injection': "improper neutralization of special elements used in an os command ('os command injection')",
  'os command injection': "improper neutralization of special elements used in an os command ('os command injection')",
  'path traversal': "improper limitation of a pathname to a restricted directory ('path traversal')",
  'directory traversal': "improper limitation of a pathname to a restricted directory ('path traversal')",
  'local file inclusion': "improper control of filename for include/require statement in php program ('php remote file inclusion')",
  'local file inclusion (lfi)': "improper control of filename for include/require statement in php program ('php remote file inclusion')",
  'insecure deserialization': "deserialization of untrusted data",
  'deserialization': "deserialization of untrusted data",
  'unrestricted file upload': "unrestricted upload of file with dangerous type",
  'file upload': "unrestricted upload of file with dangerous type",
  'open redirect': "url redirection to untrusted site ('open redirect')",
  'hardcoded credentials': "use of hard-coded credentials",
  'hardcoded secrets': "use of hard-coded credentials",
  'csrf': "cross-site request forgery (csrf)",
  'ssrf': "server-side request forgery (ssrf)",
};

let NORMALIZED_ALIASES: Record<string, string> | null = null;
function getNormalizedAliases() {
  if (!NORMALIZED_ALIASES) {
    NORMALIZED_ALIASES = {};
    for (const [k, v] of Object.entries(ALIASES)) {
      NORMALIZED_ALIASES[normalizeForMatch(k)] = normalizeForMatch(v);
    }
  }
  return NORMALIZED_ALIASES;
}

/** Singleton map: Vulnerability Type (lower-case) → record */
let _vulnMap: Map<string, VulnerabilityRecord> | null = null;

/**
 * Load and cache the dataset.  Called once from index.ts at startup.
 * Silently degrades if the file is missing or malformed.
 */
export function loadVulnerabilityDataset(csvPath: string): void {
  try {
    const abs = resolve(csvPath);
    const raw = readFileSync(abs, 'utf-8');
    const lines = raw.split('\n');
    const map = new Map<string, VulnerabilityRecord>();

    // Skip header row
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      const lastComma = line.lastIndexOf(',');
      const secondLastComma = line.lastIndexOf(',', lastComma - 1);
      const thirdLastComma = line.lastIndexOf(',', secondLastComma - 1);

      if (thirdLastComma === -1) continue;

      const epss_score = parseFloat(line.substring(lastComma + 1)) || 0;
      const impact = parseInt(line.substring(secondLastComma + 1, lastComma)) || 1;
      const likelihood = parseInt(line.substring(thirdLastComma + 1, secondLastComma)) || 1;
      let vulnType = line.substring(0, thirdLastComma).trim();
      
      if (vulnType.startsWith('"') && vulnType.endsWith('"')) {
        vulnType = vulnType.slice(1, -1).trim();
      }
      
      vulnType = vulnType.toLowerCase();

      map.set(vulnType, {
        vulnerability_type: vulnType,
        likelihood,
        impact,
        epss_score,
        normalized_type: normalizeForMatch(vulnType),
      });
    }

    _vulnMap = map;
    console.log(`[DATASET] Vulnerability dataset loaded: ${map.size.toLocaleString()} entries`);
  } catch (err) {
    console.warn('[DATASET] Vulnerability dataset not loaded (non-fatal):', (err as Error).message);
    _vulnMap = new Map();
  }
}

/** Return the cached map (never null after loadVulnerabilityDataset is called). */
export function getVulnerabilityMap(): Map<string, VulnerabilityRecord> {
  return _vulnMap ?? new Map();
}

// No derived likelihood or impact, we use it directly from CSV

/**
 * Risk-map entry returned to the frontend.
 * Coordinates are 1–5 on both axes.
 */
export interface RiskMapEntry {
  label: string;         // short vulnerability type label
  likelihood: number;    // 1–5
  impact: number;        // 1–5
  cveId?: string;        // the CVE matched, if any
  epssScore?: number;    // raw EPSS probability [0,1] or family estimate
  cisaKev?: boolean;
  enriched: boolean;     // false only when NEITHER dataset NOR family matched
}

/**
 * Extract all CVE IDs mentioned in a freeform string.
 * Returns them upper-cased and de-duplicated.
 */
export function extractCveIds(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) ?? [];
  return [...new Set(matches.map((m) => m.toUpperCase()))].sort();
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/** Map severity label → impact value (Tier 3 last resort only). */
function severityToImpact(label: string | null | undefined): number {
  switch ((label ?? '').toLowerCase()) {
    case 'critical': return 5;
    case 'high': return 4;
    case 'medium': return 3;
    case 'low': return 2;
    default: return 2;
  }
}

/** Map confidence label → likelihood value (Tier 3 last resort only). */
function confidenceToLikelihood(conf: string | null | undefined): number {
  switch ((conf ?? '').toLowerCase()) {
    case 'high': return 4;
    case 'medium': return 3;
    case 'low': return 2;
    default: return 2;
  }
}

/**
 * High-confidence patterns: direct, unambiguous vulnerable code signatures.
 * These indicate the vulnerability is clearly present and directly identifiable.
 */
const HIGH_CONFIDENCE_PATTERNS: RegExp[] = [
  /\$_GET|\$_POST|\$_REQUEST|\$_COOKIE/i,         // PHP superglobals (direct user input)
  /system\s*\(/i,                                   // OS command execution
  /exec\s*\(/i,                                     // exec() calls
  /shell_exec\s*\(/i,                               // shell_exec()
  /passthru\s*\(/i,                                 // passthru()
  /unserialize\s*\(/i,                              // PHP unserialize
  /mysql_query|mysqli_query|pg_query/i,             // raw DB queries
  /\.query\s*\(.*\+|\bquery\b.*\$\{/i,            // SQL string concatenation
  /echo\s+\$_|print\s+\$_/i,                       // echoing raw user input
  /include\s*\(\s*\$_|require\s*\(\s*\$_/i,       // dynamic file include
  /file_get_contents\s*\(\s*\$_/i,                 // SSRF / LFI pattern
  /move_uploaded_file/i,                            // file upload
  /header\s*\(\s*['"]Location:\s*.*\$_/i,          // open redirect
];

/**
 * Medium-confidence patterns: likely vulnerable but context-dependent.
 */
const MEDIUM_CONFIDENCE_PATTERNS: RegExp[] = [
  /SELECT|INSERT|UPDATE|DELETE|DROP/i,              // SQL keywords (could be safe if parameterised)
  /innerHTML|document\.write|eval\s*\(/i,           // JS XSS sinks
  /md5\s*\(|sha1\s*\(/i,                           // weak hashing
  /rand\s*\(|mt_rand\s*\(/i,                       // weak randomness
  /base64_decode\s*\(/i,                            // potential obfuscation/decode
  /\bcurl_exec\b|\bfile_get_contents\b/i,          // external requests
  /password.*plain|plain.*password/i,               // plaintext password patterns
];

/**
 * Calculate confidence in the detection based on evidence strength.
 *
 * Confidence = confidence in DETECTION, not in severity.
 * A Critical vuln can have Medium confidence; a Low vuln can have High confidence.
 *
 * Logic:
 * - High:   direct, unambiguous vulnerable code pattern identified
 * - Medium: likely vulnerable but context-dependent, alias/contains match, or indirect evidence
 * - Low:    inferred, weak evidence, or fallback-only detection
 */
export function calculateConfidence(
  vulnerabilityType: string | null,
  explanation: string,
  matchMethod: string,
  llmConfidence: string,
): { confidence: 'Low' | 'Medium' | 'High'; reason: string } {
  const combined = `${vulnerabilityType ?? ''} ${explanation}`.toLowerCase();

  // Check for direct, high-confidence code patterns in the explanation
  for (const pattern of HIGH_CONFIDENCE_PATTERNS) {
    if (pattern.test(combined)) {
      return {
        confidence: 'High',
        reason: `Direct vulnerable code pattern matched: ${pattern.toString().slice(1, 40)}...`,
      };
    }
  }

  // Dataset alias/contains match — indirect evidence, demote to Medium unless LLM says Low
  if (matchMethod === 'alias' || matchMethod === 'contains') {
    return {
      confidence: 'Medium',
      reason: `Dataset matched via ${matchMethod} — indirect evidence; confidence downgraded from ${llmConfidence}`,
    };
  }

  // Check for medium-confidence patterns
  for (const pattern of MEDIUM_CONFIDENCE_PATTERNS) {
    if (pattern.test(combined)) {
      // If LLM was Low, keep Low; otherwise Medium
      if (llmConfidence === 'Low') {
        return {
          confidence: 'Low',
          reason: `Weak SQL/JS pattern in explanation; LLM also reported Low confidence`,
        };
      }
      return {
        confidence: 'Medium',
        reason: `Indirect pattern matched: ${pattern.toString().slice(1, 40)}...`,
      };
    }
  }

  // Fallback: no match at all — trust LLM but cap at Medium if no dataset match
  if (matchMethod === 'none') {
    return {
      confidence: 'Low',
      reason: 'No dataset match and no direct code pattern found; inferred from LLM only',
    };
  }

  // Exact dataset match with no strong code patterns — trust LLM confidence
  const normalized = llmConfidence as 'Low' | 'Medium' | 'High';
  return {
    confidence: normalized,
    reason: `Exact dataset match; LLM confidence (${llmConfidence}) accepted`,
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Extended risk map entry that also carries the match metadata needed
 * by analyze.ts to compute evidence-based confidence.
 */
export interface RiskMapEntryWithMeta extends RiskMapEntry {
  _matchMethod: string;  // 'exact' | 'alias' | 'contains' | 'none'
}

export function buildRiskMap(
  vulnerabilities: Array<{
    vulnerability_type: string | null;
    owasp_category?: string | null;
    cvss_score?: number | null;
    severity_label: string | null;
    confidence: string;
    explanation?: string;
    notes?: string | null;
  }>,
  rawContent: string,
): RiskMapEntryWithMeta[] {
  const map = getVulnerabilityMap();

  console.log(`[DATASET MATCHING] Loaded dataset row count: ${map.size}`);

  return vulnerabilities.map((vuln, i) => {
    const rawType = vuln.vulnerability_type || '';
    const label = rawType || `Vuln #${i + 1}`;

    // Normalize vulnerability_type for lookup
    const normalizedAiKey = normalizeForMatch(rawType);

    let matched: VulnerabilityRecord | undefined;
    let matchMethod = 'none';

    // 1. Exact match
    for (const record of map.values()) {
      if (record.normalized_type === normalizedAiKey) {
        matched = record;
        matchMethod = 'exact';
        break;
      }
    }

    // 2. Alias match
    if (!matched) {
      const aliases = getNormalizedAliases();
      const targetNormalized = aliases[normalizedAiKey];
      if (targetNormalized) {
        for (const record of map.values()) {
          if (record.normalized_type === targetNormalized) {
            matched = record;
            matchMethod = 'alias';
            break;
          }
        }
      }
    }

    // 3. Contains match
    if (!matched && normalizedAiKey) {
      for (const record of map.values()) {
        const dsKey = record.normalized_type || '';
        if (dsKey && (dsKey.includes(normalizedAiKey) || normalizedAiKey.includes(dsKey))) {
          matched = record;
          matchMethod = 'contains';
          break;
        }
      }
    }

    if (matched) {
      // ── Dataset match: use dataset likelihood, impact, EPSS for Risk Map ONLY.
      // DO NOT touch severity_label — that is owned exclusively by the CVSS vector.
      const candidateCves = [...extractCveIds(vuln.notes ?? ''), ...extractCveIds(rawContent)];
      const matchedId = candidateCves[0];

      return {
        label,
        likelihood: matched.likelihood,
        impact: matched.impact,
        cveId: matchedId,
        epssScore: matched.epss_score,
        enriched: true,
        _matchMethod: matchMethod,
      };
    }

    // ── Fallback: LLM severity + confidence heuristic (last resort) ────────────
    return {
      label,
      likelihood: confidenceToLikelihood(vuln.confidence),
      impact: severityToImpact(vuln.severity_label),
      enriched: false,
      _matchMethod: 'none',
    };
  });
}

