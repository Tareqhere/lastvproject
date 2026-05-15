/**
 * CVSS v3.1 Score Computation Service.
 *
 * Implements the CVSS v3.1 scoring algorithm to compute base scores from
 * vector strings. This provides server-side verification/computation of
 * CVSS scores independent of the LLM's estimation.
 *
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 *
 * ASSUMPTIONS & LIMITATIONS:
 * - Only Base Score metrics are computed (not Temporal or Environmental).
 * - If the LLM provides a CVSS vector, we parse and compute the score.
 * - If no vector is provided but a severity label is given, we use a
 *   representative score from the middle of the severity range.
 * - Partial or malformed vectors are handled gracefully with fallbacks.
 */
// CVSS v3.1 metric value mappings
const METRIC_VALUES = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 }, // Attack Vector
    AC: { L: 0.77, H: 0.44 }, // Attack Complexity
    PR: {
        N: 0.85, L: 0.62, H: 0.27,
    },
    PR_CHANGED: {
        N: 0.85, L: 0.68, H: 0.50,
    },
    UI: { N: 0.85, R: 0.62 }, // User Interaction
    S: { U: 'unchanged', C: 'changed' }, // Scope
    C: { H: 0.56, L: 0.22, N: 0 }, // Confidentiality Impact
    I: { H: 0.56, L: 0.22, N: 0 }, // Integrity Impact
    A: { H: 0.56, L: 0.22, N: 0 }, // Availability Impact
};
// Severity label mapping from numeric CVSS score
const SEVERITY_RANGES = [
    { max: 0.0, label: 'None' },
    { max: 3.9, label: 'Low' },
    { max: 6.9, label: 'Medium' },
    { max: 8.9, label: 'High' },
    { max: 10.0, label: 'Critical' },
];
// Representative scores for severity labels (middle of range)
const SEVERITY_TO_SCORE = {
    None: 0.0,
    Low: 2.0,
    Medium: 5.5,
    High: 7.5,
    Critical: 9.5,
};
/**
 * Parse a CVSS v3.1 vector string and compute the base score.
 * Expected format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
 */
export function computeCvssScore(vector) {
    try {
        // Validate vector prefix
        if (!vector.startsWith('CVSS:3.1/') && !vector.startsWith('CVSS:3.0/')) {
            return { cvss_score: null, cvss_vector: vector, severity_label: null };
        }
        const metricsStr = vector.replace(/^CVSS:3\.[01]\//, '');
        const parts = metricsStr.split('/');
        const metrics = {};
        for (const part of parts) {
            const [key, value] = part.split(':');
            if (key && value) {
                metrics[key] = value;
            }
        }
        // Verify all required base metrics are present
        const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
        for (const r of required) {
            if (!metrics[r]) {
                return { cvss_score: null, cvss_vector: vector, severity_label: null };
            }
        }
        const scopeChanged = metrics['S'] === 'C';
        // Get metric numeric values
        const av = METRIC_VALUES.AV[metrics['AV']];
        const ac = METRIC_VALUES.AC[metrics['AC']];
        const pr = scopeChanged
            ? METRIC_VALUES.PR_CHANGED[metrics['PR']]
            : METRIC_VALUES.PR[metrics['PR']];
        const ui = METRIC_VALUES.UI[metrics['UI']];
        const c = METRIC_VALUES.C[metrics['C']];
        const i = METRIC_VALUES.I[metrics['I']];
        const a = METRIC_VALUES.A[metrics['A']];
        if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) {
            return { cvss_score: null, cvss_vector: vector, severity_label: null };
        }
        // Compute Impact Sub Score (ISS)
        const iss = 1 - (1 - c) * (1 - i) * (1 - a);
        // Compute Impact
        let impact;
        if (scopeChanged) {
            impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        }
        else {
            impact = 6.42 * iss;
        }
        // If impact is <= 0, score is 0
        if (impact <= 0) {
            return { cvss_score: 0.0, cvss_vector: vector, severity_label: 'None' };
        }
        // Compute Exploitability
        const exploitability = 8.22 * av * ac * pr * ui;
        // Compute Base Score
        let score;
        if (scopeChanged) {
            score = Math.min(1.08 * (impact + exploitability), 10);
        }
        else {
            score = Math.min(impact + exploitability, 10);
        }
        // Round up to nearest tenth
        score = Math.ceil(score * 10) / 10;
        return {
            cvss_score: score,
            cvss_vector: vector,
            severity_label: getSeverityLabel(score),
        };
    }
    catch {
        return { cvss_score: null, cvss_vector: vector, severity_label: null };
    }
}
/**
 * Get severity label from a numeric CVSS score.
 */
export function getSeverityLabel(score) {
    if (score === 0)
        return 'None';
    for (const range of SEVERITY_RANGES) {
        if (score <= range.max)
            return range.label;
    }
    return 'Critical';
}
/**
 * Estimate a CVSS score from a severity label when no vector is available.
 * Documents this is an approximation using mid-range representative values.
 */
export function estimateScoreFromLabel(label) {
    const score = SEVERITY_TO_SCORE[label];
    if (score !== undefined) {
        return { cvss_score: score, cvss_vector: null, severity_label: label };
    }
    return { cvss_score: null, cvss_vector: null, severity_label: null };
}
