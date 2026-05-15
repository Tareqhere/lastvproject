/**
 * MITRE ATT&CK enrichment layer — CSV-first, AI fallback.
 *
 * Loads `vulnerability_mitre_enriched.csv` once at startup into a
 * normalised in-memory Map.  For every vulnerability the analysis
 * pipeline detects, it tries to find a matching row in the CSV and
 * returns the authoritative MITRE mapping from there.  Only when no
 * match is found does it fall through to whatever the LLM produced.
 *
 * CSV columns (in order):
 *   vulnerability_type, mitre_attack_id, mitre_attack_technique,
 *   mitre_description, mitre_url
 *
 * IMPORTANT:
 * - This service ONLY touches `mitre_attack_mapping` on each vuln.
 * - It NEVER modifies CVSS, severity, confidence, OWASP, or any
 *   other field.
 * - It adds no new visible fields to the API response.
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MitreRecord {
  vulnerability_type: string;  // normalised key (lowercase, spaces)
  technique_id: string;        // e.g. "T1190"
  technique_name: string;      // e.g. "Exploit Public-Facing Application"
  description: string;         // mitre_description from CSV
  url: string;                 // mitre_url from CSV
}

/** The shape expected by the report's mitre_attack_mapping array. */
export interface MitreAttackEntry {
  technique_id: string;
  technique_name: string;
  explanation: string;
}

// ─── Normalisation ────────────────────────────────────────────────────────────

/**
 * Normalise a vulnerability name for fuzzy matching.
 * - lowercase, trim
 * - replace "-", "_", "/" with spaces
 * - collapse extra spaces
 * Intentionally kept lightweight so it stays consistent with
 * the normalisation already used in cveLookup.ts.
 */
function normaliseName(s: string): string {
  if (!s) return '';
  return s
    .toLowerCase()
    .trim()
    .replace(/[-_/]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// ─── Aliases (expand before CSV lookup) ──────────────────────────────────────

/**
 * Common acronyms / shorthand → canonical name that appears in the CSV.
 * Applied BEFORE the CSV lookup so an AI that returns "XSS" still hits
 * the "cross-site scripting" row.
 */
const MITRE_ALIASES: Record<string, string> = {
  'xss':   'cross site scripting',
  'csrf':  'cross site request forgery',
  'ssrf':  'server side request forgery',
  'idor':  'insecure direct object reference',
  'xxe':   'xml external entity injection',
  'rce':   'remote code execution',
  'sqli':  'sql injection',
  'lfi':   'local file inclusion',
  'rfi':   'remote file inclusion',
};

// ─── In-memory cache ──────────────────────────────────────────────────────────

/** Singleton: normalised vulnerability name → MitreRecord */
let _mitreMap: Map<string, MitreRecord> | null = null;

// ─── CSV parsing ──────────────────────────────────────────────────────────────

/**
 * Parse a single CSV line that may contain quoted fields (fields that
 * contain commas are wrapped in double-quotes by Excel/Google Sheets).
 *
 * We only need to handle the MITRE CSV structure here:
 *   vulnerability_type, mitre_attack_id, mitre_attack_technique,
 *   mitre_description (quoted, may contain commas/newlines), mitre_url
 *
 * Strategy: find the first comma (col 0), the second comma (col 1),
 * the third comma (col 2), then treat the rest as the quoted block +
 * the URL at the very end.
 */
function parseMitreLine(line: string): [string, string, string, string, string] | null {
  // col 0: vulnerability_type (never quoted in this CSV)
  const c0 = line.indexOf(',');
  if (c0 === -1) return null;

  // col 1: mitre_attack_id
  const c1 = line.indexOf(',', c0 + 1);
  if (c1 === -1) return null;

  // col 2: mitre_attack_technique
  const c2 = line.indexOf(',', c1 + 1);
  if (c2 === -1) return null;

  const vulnType       = line.substring(0, c0).trim();
  const mitreId        = line.substring(c0 + 1, c1).trim();
  const mitreTechnique = line.substring(c1 + 1, c2).trim();

  // col 3: mitre_description (may be quoted with embedded commas/newlines)
  // col 4: mitre_url (always the very last field)
  const remainder = line.substring(c2 + 1);

  let description: string;
  let url: string;

  if (remainder.startsWith('"')) {
    // Quoted field — find the closing quote that is NOT doubled ("")
    let i = 1;
    while (i < remainder.length) {
      if (remainder[i] === '"') {
        if (remainder[i + 1] === '"') {
          i += 2; // escaped quote, skip both
        } else {
          break;  // end of quoted field
        }
      } else {
        i++;
      }
    }
    description = remainder.substring(1, i).replace(/""/g, '"');
    // The URL follows the closing quote + comma
    url = remainder.substring(i + 2).trim(); // +2: skip closing " and comma
  } else {
    // Unquoted — split on the last comma
    const lastComma = remainder.lastIndexOf(',');
    if (lastComma === -1) {
      description = remainder.trim();
      url = '';
    } else {
      description = remainder.substring(0, lastComma).trim();
      url         = remainder.substring(lastComma + 1).trim();
    }
  }

  if (!vulnType || !mitreId || !mitreTechnique) return null;
  return [vulnType, mitreId, mitreTechnique, description, url];
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Load and cache the MITRE enrichment CSV.
 * Should be called once at application startup (e.g. from index.ts).
 * If the file is missing or unparseable, logs a warning and keeps the
 * map empty so the AI fallback remains in full effect.
 */
export function loadMitreDataset(csvPath: string): void {
  try {
    const abs = resolve(csvPath);
    const raw = readFileSync(abs, 'utf-8');

    // The CSV contains multi-line quoted fields, so we cannot simply
    // split on '\n'.  Instead we re-assemble logical lines ourselves.
    const logicalLines: string[] = [];
    let current = '';
    let inQuote  = false;

    for (let ci = 0; ci < raw.length; ci++) {
      const ch = raw[ci];
      if (ch === '"') {
        if (inQuote && raw[ci + 1] === '"') {
          current += '""';
          ci++;
        } else {
          inQuote = !inQuote;
          current += ch;
        }
      } else if (ch === '\n' && !inQuote) {
        logicalLines.push(current);
        current = '';
      } else if (ch === '\r') {
        // ignore CR
      } else {
        current += ch;
      }
    }
    if (current.trim()) logicalLines.push(current);

    const map = new Map<string, MitreRecord>();

    // Skip header (index 0)
    for (let i = 1; i < logicalLines.length; i++) {
      const line = logicalLines[i].trim();
      if (!line) continue;

      const parsed = parseMitreLine(line);
      if (!parsed) continue;

      const [vulnType, mitreId, mitreTechnique, description, url] = parsed;
      const key = normaliseName(vulnType);
      if (!key) continue;

      // First occurrence wins (the CSV may have duplicate vulnerability_type rows
      // that all share the same MITRE mapping — taking the first is fine)
      if (!map.has(key)) {
        map.set(key, {
          vulnerability_type: key,
          technique_id:   mitreId,
          technique_name: mitreTechnique,
          description,
          url,
        });
      }
    }

    _mitreMap = map;
    console.log(`[MITRE] MITRE enrichment CSV loaded: ${map.size} unique vulnerability types`);
  } catch (err) {
    console.warn('[MITRE] MITRE enrichment CSV not loaded (non-fatal):', (err as Error).message);
    console.warn('[MITRE] Falling back to AI-generated MITRE mapping for all vulnerabilities.');
    _mitreMap = new Map(); // empty → AI fallback for everything
  }
}

/**
 * Look up a vulnerability type in the MITRE CSV.
 *
 * Resolution order:
 *   1. Direct normalised match against the CSV
 *   2. Alias expansion (xss → cross site scripting, etc.) then match
 *   3. Returns null → caller should use AI-generated mapping
 *
 * @param vulnerabilityType  Raw string from the LLM (e.g. "SQL Injection")
 * @returns MitreRecord if found in CSV, otherwise null
 */
export function lookupMitreFromCsv(vulnerabilityType: string): MitreRecord | null {
  if (!_mitreMap) return null; // dataset not loaded yet
  if (!vulnerabilityType) return null;

  const key = normaliseName(vulnerabilityType);

  // 1. Direct match
  const direct = _mitreMap.get(key);
  if (direct) {
    console.log(`[MITRE] CSV hit (direct): "${vulnerabilityType}" → ${direct.technique_id}`);
    return direct;
  }

  // 2. Alias match
  const aliasTarget = MITRE_ALIASES[key];
  if (aliasTarget) {
    const aliased = _mitreMap.get(aliasTarget);
    if (aliased) {
      console.log(`[MITRE] CSV hit (alias): "${vulnerabilityType}" → "${aliasTarget}" → ${aliased.technique_id}`);
      return aliased;
    }
  }

  console.log(`[MITRE] CSV miss — AI fallback for: "${vulnerabilityType}"`);
  return null;
}

/**
 * Apply MITRE CSV enrichment to a single vulnerability's
 * mitre_attack_mapping array.
 *
 * - If the CSV has a match, replace the mapping entirely with one
 *   authoritative entry from the CSV.
 * - If no CSV match, return the array unchanged (AI-generated mapping
 *   stays in place).
 *
 * The returned array always has the same structure the frontend already
 * expects: [{ technique_id, technique_name, explanation }]
 */
export function enrichMitreMapping(
  vulnerabilityType: string | null,
  aiMapping: MitreAttackEntry[] | null | undefined,
): MitreAttackEntry[] {
  const record = lookupMitreFromCsv(vulnerabilityType ?? '');

  if (record) {
    // CSV wins — build one canonical entry
    return [
      {
        technique_id:   record.technique_id,
        technique_name: record.technique_name,
        explanation:    record.description,
      },
    ];
  }

  // No CSV match — keep whatever the AI returned (may be empty array)
  return aiMapping ?? [];
}
