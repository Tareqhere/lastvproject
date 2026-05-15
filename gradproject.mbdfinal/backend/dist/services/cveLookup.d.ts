export interface CveRecord {
    cve_id: string;
    likelihood: number;
    impact: number;
    epss_score: number;
}
/**
 * Load and cache the dataset.  Called once from index.ts at startup.
 * Silently degrades if the file is missing or malformed.
 */
export declare function loadCveDataset(csvPath: string): void;
/** Return the cached map (never null after loadCveDataset is called). */
export declare function getCveMap(): Map<string, CveRecord>;
/** Look up a single CVE record by ID (case-insensitive). */
export declare function lookupCve(cveId: string): CveRecord | undefined;
/**
 * Risk-map entry returned to the frontend.
 * Coordinates are 1–5 on both axes.
 */
export interface RiskMapEntry {
    label: string;
    likelihood: number;
    impact: number;
    cveId?: string;
    epssScore?: number;
    cisaKev?: boolean;
    enriched: boolean;
}
/**
 * Extract all CVE IDs mentioned in a freeform string.
 * Returns them upper-cased and de-duplicated.
 */
export declare function extractCveIds(text: string): string[];
/** Severity threshold overrides based on EPSS score */
export declare function getSeverityFromEpss(epss: number): string;
/**
 * Build a RiskMapEntry array from vulnerabilities + raw input content.
 * Overrides the LLM's severity_label with EPSS-based severity if a match is found.
 */
export declare function buildRiskMap(vulnerabilities: Array<{
    vulnerability_type: string | null;
    owasp_category?: string | null;
    severity_label: string | null;
    confidence: string;
    explanation?: string;
    notes?: string | null;
}>, rawContent: string): RiskMapEntry[];
