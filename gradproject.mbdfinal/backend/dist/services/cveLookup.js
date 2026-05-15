/**
 * CVE/EPSS enrichment layer.
 *
 * Loads the local CSV dataset ONCE at startup into an in-memory Map.
 * All subsequent lookups are O(1) hash-map accesses.
 */
import { readFileSync } from 'fs';
import { resolve } from 'path';
/** Singleton map: CVE-ID (upper-case) → record */
let _cveMap = null;
/**
 * Load and cache the dataset.  Called once from index.ts at startup.
 * Silently degrades if the file is missing or malformed.
 */
export function loadCveDataset(csvPath) {
    try {
        const abs = resolve(csvPath);
        const raw = readFileSync(abs, 'utf-8');
        const lines = raw.split('\n');
        const map = new Map();
        // Skip header row
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line)
                continue;
            const cols = line.split(',');
            if (cols.length < 4)
                continue;
            const cveId = cols[0].trim().toUpperCase();
            map.set(cveId, {
                cve_id: cveId,
                likelihood: parseInt(cols[1]) || 1,
                impact: parseInt(cols[2]) || 1,
                epss_score: parseFloat(cols[3]) || 0,
            });
        }
        _cveMap = map;
        console.log(`[CVE] Dataset loaded: ${map.size.toLocaleString()} entries`);
    }
    catch (err) {
        console.warn('[CVE] Dataset not loaded (non-fatal):', err.message);
        _cveMap = new Map();
    }
}
/** Return the cached map (never null after loadCveDataset is called). */
export function getCveMap() {
    return _cveMap ?? new Map();
}
/** Look up a single CVE record by ID (case-insensitive). */
export function lookupCve(cveId) {
    return _cveMap?.get(cveId.toUpperCase());
}
/**
 * Extract all CVE IDs mentioned in a freeform string.
 * Returns them upper-cased and de-duplicated.
 */
export function extractCveIds(text) {
    const matches = text.match(/CVE-\d{4}-\d{4,}/gi) ?? [];
    return [...new Set(matches.map((m) => m.toUpperCase()))].sort();
}
/** Severity threshold overrides based on EPSS score */
export function getSeverityFromEpss(epss) {
    if (epss >= 0.5)
        return 'Critical';
    if (epss >= 0.2)
        return 'High';
    if (epss >= 0.05)
        return 'Medium';
    return 'Low';
}
// ─── Internal helpers ─────────────────────────────────────────────────────────
/** Map severity label → impact value (Tier 3 last resort only). */
function severityToImpact(label) {
    switch ((label ?? '').toLowerCase()) {
        case 'critical': return 5;
        case 'high': return 4;
        case 'medium': return 3;
        case 'low': return 2;
        default: return 2;
    }
}
/** Map confidence label → likelihood value (Tier 3 last resort only). */
function confidenceToLikelihood(conf) {
    switch ((conf ?? '').toLowerCase()) {
        case 'high': return 4;
        case 'medium': return 3;
        case 'low': return 2;
        default: return 2;
    }
}
// ─── Public API ───────────────────────────────────────────────────────────────
/**
 * Build a RiskMapEntry array from vulnerabilities + raw input content.
 * Overrides the LLM's severity_label with EPSS-based severity if a match is found.
 */
export function buildRiskMap(vulnerabilities, rawContent) {
    const contentCves = extractCveIds(rawContent);
    const map = getCveMap();
    return vulnerabilities.map((vuln, i) => {
        const label = vuln.vulnerability_type || `Vuln #${i + 1}`;
        // ── Tier 1: Exact CVE-ID lookup ──────────────────────────────────────────
        const noteCves = extractCveIds(vuln.notes ?? '');
        const candidateCves = [...noteCves, ...contentCves];
        let matched;
        let matchedId;
        for (const id of candidateCves) {
            const rec = map.get(id);
            if (rec) {
                matched = rec;
                matchedId = id;
                break;
            }
        }
        if (matched) {
            // OVERRIDE LLM severity using EPSS
            vuln.severity_label = getSeverityFromEpss(matched.epss_score);
            return {
                label,
                likelihood: matched.likelihood,
                impact: matched.impact,
                cveId: matchedId,
                epssScore: matched.epss_score,
                enriched: true,
            };
        }
        // ── Tier 2: LLM severity + confidence heuristic (last resort) ────────────
        return {
            label,
            likelihood: confidenceToLikelihood(vuln.confidence),
            impact: severityToImpact(vuln.severity_label),
            enriched: false,
        };
    });
}
