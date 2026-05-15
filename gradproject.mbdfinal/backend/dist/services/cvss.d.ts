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
export interface CvssResult {
    cvss_score: number | null;
    cvss_vector: string | null;
    severity_label: string | null;
}
/**
 * Parse a CVSS v3.1 vector string and compute the base score.
 * Expected format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
 */
export declare function computeCvssScore(vector: string): CvssResult;
/**
 * Get severity label from a numeric CVSS score.
 */
export declare function getSeverityLabel(score: number): string;
/**
 * Estimate a CVSS score from a severity label when no vector is available.
 * Documents this is an approximation using mid-range representative values.
 */
export declare function estimateScoreFromLabel(label: string): CvssResult;
